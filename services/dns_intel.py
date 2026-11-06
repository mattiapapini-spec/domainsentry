"""
DNS Intelligence Service (:8001)
Modulo 1 estratto dal monolite — DNS completo + DMARC/DKIM/BIMI/CAA + sottodomini.
"""

import os, logging, re, time
from fastapi import FastAPI, APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_log_input
from shared.utils import dig_lookup, now_iso
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

app = FastAPI(title="DNS Intel", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("dns-intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DNS] %(message)s")

DNS_TIMEOUT = int(os.environ.get("DNS_TIMEOUT", "10"))

# SEC-29: durata massima di una richiesta `/dns`, sotto il timeout con cui
# l'orchestrator la aspetta (45 s di default): oltre, la risposta andrebbe persa
# mentre il gestore resta occupato con i suoi `dig`. Letta a ogni richiesta.
DNS_DEADLINE_S = 40

# SEC-26: ogni selettore diventa un processo `dig` (8 in parallelo, fino a
# timeout+10 s ciascuno) e il primo carattere del nome passato a `dig`. Il tetto
# a 32 lascia il default (18) con margine e tiene il caso peggiore dello stadio
# DKIM nell'ordine di ~80 s. La sintassi è `selector` di RFC 6376 §3.5: label
# separate da `.`, ciascuna alfanumerica con `-` interni, di al più 63 caratteri.
MAX_DKIM_SELECTORS = 32
_DKIM_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DKIM_SELECTOR_RE = re.compile(rf"{_DKIM_LABEL}(?:\.{_DKIM_LABEL})*")

# RES-01: testo fisso di `error` quando nessuno dei 7 tipi base ha risposto. Non
# riecheggia l'output di `dig` (indirizzi del resolver, righe `;;`) né il dominio.
DNS_ALL_UNKNOWN_ERROR = "DNS resolution failed: no base record type could be resolved"


@app.get("/health")
def health():
    return {"status": "healthy", "service": "dns-intel", "version": "4.0.0"}


@router.get("/dns", tags=["DNS Intelligence"])
def dns_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    full: bool = Query(False, description="Include DMARC/DKIM/BIMI/CAA"),
    subdomains: bool = Query(False, description="Enumerate subdomains"),
    dkim_selectors: str = Query("", max_length=2048, description="Comma-separated selectors override")
):
    logger.info(f"Check: {sanitize_log_input(domain)} full={full} sub={subdomains}")

    # SEC-26: validazione d'ingresso, prima di qualunque `dig` (anche con full=false),
    # come per `domain`. Il testo dell'errore non riecheggia l'input.
    selectors = dkim_selectors.split(",") if dkim_selectors else DEFAULT_DKIM_SELECTORS
    selectors = [s.strip() for s in selectors if s.strip()]
    if len(selectors) > MAX_DKIM_SELECTORS or not all(_DKIM_SELECTOR_RE.fullmatch(s) for s in selectors):
        raise HTTPException(422, f"Invalid dkim_selectors: max {MAX_DKIM_SELECTORS} selectors, each made of "
                                 "dot-separated labels of letters, digits and '-' (1-63 chars, "
                                 "not starting or ending with '-')")

    result = {
        "domain": domain, "timestamp": now_iso(),
        "records": {}, "records_status": {}, "email_auth": {}, "subdomains": {},
        "error": None
    }

    # RES-01: ogni query dà (stato, record). `unknown` = il DNS non ha risposto
    # (SERVFAIL, REFUSED, trasporto, pacchetto non parsabile) e non vale "nessun
    # record": i record restano `[]` come prima, lo stato lo dichiara. I worker dei
    # pool scrivono qui in parallelo: `list.append` è atomico, un contatore no.
    unknown_queries = []
    # SEC-29: la scadenza è fissata qui, una per richiesta. Ogni query riceve il tempo
    # che resta (`dig` ucciso allo scadere) e, esaurito quello, non parte: in entrambi
    # i casi è `unknown` come ogni query senza esito, mai "nessun record".
    deadline = time.monotonic() + DNS_DEADLINE_S

    def _lookup(fqdn, rtype):
        status, rec = dig_lookup(fqdn, rtype, DNS_TIMEOUT, limit=deadline - time.monotonic())
        if status == "unknown":
            unknown_queries.append(fqdn)
        return status, rec

    # Record base, i 7 tipi insieme: in serie due tipi che non rispondono basterebbero a
    # consumare la scadenza di tutti gli altri. 7 `dig`, meno dei 10 dello stadio dei
    # sottodomini; `map` restituisce nell'ordine dato, quindi l'ordine delle chiavi resta.
    from concurrent.futures import ThreadPoolExecutor
    base_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    with ThreadPoolExecutor(max_workers=len(base_types)) as ex:
        for rtype, answer in zip(base_types, ex.map(lambda t: _lookup(domain, t), base_types), strict=True):
            result["records_status"][rtype], result["records"][rtype] = answer

    # RES-01: con tutti e 7 i tipi base `unknown` il modulo non ha raccolto nulla:
    # `error` valorizzato è ciò che lo fa leggere come fallito a `collection_failed`
    # (prima era sempre `None`). Calcolato qui, prima dell'uscita di `full=false`.
    if all(status == "unknown" for status in result["records_status"].values()):
        result["error"] = DNS_ALL_UNKNOWN_ERROR

    if not full:
        _warn_unknown_queries(domain, len(unknown_queries))
        return JSONResponse(content=result)

    # SPF (estratto da TXT)
    spf_records = [t for t in result["records"].get("TXT", []) if "v=spf1" in t]
    result["email_auth"]["spf"] = {
        "present": bool(spf_records),
        "records": spf_records,
        "policy": _extract_spf_policy(spf_records[0]) if spf_records else None,
        "status": result["records_status"]["TXT"]
    }

    # DMARC
    dmarc_status, dmarc = _lookup(f"_dmarc.{domain}", "TXT")
    result["email_auth"]["dmarc"] = {
        "present": bool(dmarc),
        "records": dmarc,
        "status": dmarc_status
    }

    # DKIM (parallelo — 18 selettori concorrenti)
    dkim_found = {}
    dkim_unknown = []

    def _check_selector(sel):
        status, dk = _lookup(f"{sel}._domainkey.{domain}", "TXT")
        return sel, status, dk

    with ThreadPoolExecutor(max_workers=8) as ex:
        for sel, status, dk in ex.map(_check_selector, selectors):
            if dk:
                dkim_found[sel] = dk
            elif status == "unknown":
                dkim_unknown.append(sel)

    result["email_auth"]["dkim"] = {
        "selectors_found": list(dkim_found.keys()),
        "selectors_tested": len(selectors),
        "records": dkim_found,
        "selectors_unknown": dkim_unknown
    }

    # BIMI
    bimi_status, bimi = _lookup(f"default._bimi.{domain}", "TXT")
    result["email_auth"]["bimi"] = {
        "present": bool(bimi),
        "records": bimi,
        "status": bimi_status
    }

    # CAA
    caa_status, caa = _lookup(domain, "CAA")
    result["email_auth"]["caa"] = {
        "present": bool(caa),
        "records": caa,
        "status": caa_status
    }

    # Sottodomini (parallelo — 25 sottodomini concorrenti)
    if subdomains:
        def _check_sub(sub):
            fqdn = f"{sub}.{domain}"
            a_status, a = _lookup(fqdn, "A")
            c_status, c = _lookup(fqdn, "CNAME")
            sub_result = {
                "fqdn": fqdn,
                "A": a,
                "CNAME": c
            }
            return sub_result, "unknown" in (a_status, c_status)

        active = []
        sub_unknown = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            for res, unknown in ex.map(_check_sub, DEFAULT_SUBDOMAINS):
                if res["A"] or res["CNAME"]:
                    active.append(res)
                elif unknown:
                    # Non attivo ma non verificabile: diverso da "non esiste".
                    sub_unknown.append(res["fqdn"])
        result["subdomains"] = {
            "tested": len(DEFAULT_SUBDOMAINS),
            "active": active,
            "unknown": sub_unknown
        }

    _warn_unknown_queries(domain, len(unknown_queries))
    return JSONResponse(content=result)


def _warn_unknown_queries(domain: str, count: int):
    # Un solo avviso per richiesta, col solo conteggio: l'operatore vede il guasto
    # del DNS senza leggere il JSON, e il testo di `dig` non finisce nel log.
    if count:
        logger.warning("DNS: %d query senza esito (unknown) per %s", count, sanitize_log_input(domain))


def _extract_spf_policy(spf: str) -> str:
    if "-all" in spf: return "fail"
    if "~all" in spf: return "softfail"
    if "?all" in spf: return "neutral"
    if "+all" in spf: return "pass"
    return "unknown"

app.include_router(router)
