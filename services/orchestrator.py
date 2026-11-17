"""
Orchestrator Service (:8010)
Coordina la pipeline: legge il feed, chiama i servizi, pubblica eventi.
"""

import os, copy, logging, time, threading
from collections import OrderedDict
from fastapi import FastAPI, APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from urllib.parse import quote
import requests

from shared.security import apply_security, sanitize_log_input
from shared.utils import (now_iso, collection_failed, dns_unknown_rtypes, reputation_source_unobserved,
                          _calc_score, _score_to_level)
from shared import intel_store
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

app = FastAPI(title="Orchestrator", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("orchestrator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [ORCH] %(message)s")

# Service URLs (configurabili via env)
FEED_URL = os.environ.get("FEED_URL", "http://feed-manager:8000")
DNS_URL = os.environ.get("DNS_URL", "http://dns-intel:8001")
CERT_URL = os.environ.get("CERT_URL", "http://cert-intel:8002")
HTTP_URL = os.environ.get("HTTP_URL", "http://http-fingerprint:8003")
WHOIS_URL = os.environ.get("WHOIS_URL", "http://whois-intel:8004")
REP_URL = os.environ.get("REP_URL", "http://reputation:8005")
TWIST_URL = os.environ.get("TWIST_URL", "http://dnstwist-engine:8006")
CLASSIFY_URL = os.environ.get("CLASSIFY_URL", "http://classifier:8007")
EVENT_URL = os.environ.get("EVENT_URL", "http://event-publisher:8011")

# Auto case ingestion (opt-in). When true, each pipeline event is also pushed
# to the case-manager as a manageable case. Requires the case-manager running
# and a service token with manage_cases permission.
CASE_INGEST = os.environ.get("CASE_INGEST", "false").lower() == "true"
CASE_MANAGER_URL = os.environ.get("CASE_MANAGER_URL", "http://case-manager:8012")
CASE_INGEST_TOKEN = os.environ.get("CASE_INGEST_TOKEN", "")

# Intelligence persistence (opt-in): store full per-domain snapshot + diff history
# for the dashboard Intelligence tab.
INTEL_STORE = os.environ.get("INTEL_STORE", "false").lower() == "true"

# Map auto_classification → case severity
CLASSIFICATION_SEVERITY = {
    "phishing": "CRITICAL", "phishing-kit": "CRITICAL", "malware": "CRITICAL",
    "redirect-kit": "HIGH", "redirect-chain": "HIGH", "suspicious": "HIGH",
    "needs_review": "MEDIUM", "mx_only": "MEDIUM",
    "parking": "LOW", "inactive": "LOW", "benign": "LOW", "legitimate": "LOW",
    "legitimate_probable": "LOW", "likely_third_party": "LOW", "for_sale": "LOW",
    # CODE-15 + CODE-14: la decisione utente 2026-08-01 (declassare a LOW) è stata
    # ribaltata il 2026-08-04 — il security-reviewer ha mostrato che il declassamento
    # scattava sul solo fallimento di un modulo opzionale (cert via crt.sh, instabile;
    # reputation per esaurimento quote VT/OTX/ST durante scan ad alto volume), senza
    # alcuna azione dell'attaccante: un premio gratuito alla deprioritizzazione.
    # Dati incompleti != benigno: il caso resta in coda al triage, non si declassa.
    "insufficient_data": "MEDIUM",
}

TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", "45"))
PIPELINE_MAX_DURATION = int(os.environ.get("PIPELINE_MAX_DURATION", "7200"))  # 2h max
# If the pipeline's heartbeat stops advancing for this long, consider it dead and allow
# a new run. Covers crashes/kills that skip the normal cleanup. Default 10 minutes.
HEARTBEAT_STALE_SEC = int(os.environ.get("HEARTBEAT_STALE_SEC", "600"))

_lock = threading.Lock()
_running = False
_run_started = 0.0

# ── Pipeline progress + log telemetry (read via /progress) ──
# Updated as the pipeline advances so the dashboard can show real progress,
# not a fake animation. _progress holds structured state; _log_buffer holds
# the last N log lines of the current run.
_MAX_LOG_LINES = 200
_progress = {
    "running": False,
    "phase": "idle",          # idle | starting | scanning | dnstwist | done | error
    "client": None,
    "current_domain": None,
    "done": 0,                # domains processed so far
    "total": 0,               # domains known to process (grows as dnstwist discovers)
    "started_at": None,
    "finished_at": None,
    "events": 0,
}
_log_buffer = []
_last_heartbeat = 0.0  # monotonic time of the last progress update; detects dead pipelines

def _progress_set(**kw):
    """Thread-safe update of the progress state. Also bumps the heartbeat, so a
    pipeline that stops making progress (crashed / killed) can be detected as stale."""
    global _last_heartbeat
    with _lock:
        _progress.update(kw)
        _last_heartbeat = time.time()

def _progress_reset(client, total):
    global _last_heartbeat
    with _lock:
        _progress.update({
            "running": True, "phase": "starting", "client": client or "all",
            "current_domain": None, "done": 0, "total": total,
            "started_at": now_iso(), "finished_at": None, "events": 0,
        })
        _last_heartbeat = time.time()
        _log_buffer.clear()

def _plog(msg):
    """Append a line to the in-memory log buffer (and the normal logger)."""
    logger.info(msg)
    with _lock:
        _log_buffer.append({"ts": now_iso(), "msg": sanitize_log_input(str(msg))})
        if len(_log_buffer) > _MAX_LOG_LINES:
            del _log_buffer[0:len(_log_buffer) - _MAX_LOG_LINES]

# Shared session with connection pooling (reuses TCP/TLS connections)
_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "orchestrator", "version": "4.0.0",
            "running": _running}


@router.get("/status", tags=["Pipeline"])
def status():
    """Stato operativo con health check di tutti i servizi."""
    services = {}
    for name, url in [("feed-manager", FEED_URL), ("dns-intel", DNS_URL),
                       ("cert-intel", CERT_URL), ("http-fingerprint", HTTP_URL),
                       ("whois-intel", WHOIS_URL), ("reputation", REP_URL),
                       ("dnstwist-engine", TWIST_URL), ("classifier", CLASSIFY_URL),
                       ("event-publisher", EVENT_URL)]:
        try:
            r = _session.get(f"{url}/health", timeout=5)
            services[name] = "healthy" if r.ok else f"HTTP {r.status_code}"
        except Exception as e:
            services[name] = f"unreachable: {e}"

    # Feed info
    try:
        r = _session.get(f"{FEED_URL}/feed/clients", timeout=5)
        clients = r.json().get("total", 0) if r.ok else 0
    except Exception:
        clients = 0

    return {
        "status": "operational" if all(v == "healthy" for v in services.values()) else "degraded",
        "timestamp": now_iso(),
        "running": _running,
        "clients": clients,
        "services": services
    }


@router.get("/progress", tags=["Pipeline"])
def progress(include_log: bool = True):
    """
    Real progress of the running (or last) pipeline: phase, current domain,
    done/total counts, plus the recent log lines. Used by the dashboard's
    Scan progress view. Reflects actual pipeline state, not an estimate.
    """
    with _lock:
        state = dict(_progress)
        state["log"] = list(_log_buffer) if include_log else []
    # Derive a percentage when we have a total to compare against
    total = state.get("total") or 0
    done = state.get("done") or 0
    state["percent"] = round(100 * done / total) if total > 0 else (100 if state["phase"] == "done" else 0)
    return state


class TriggerRequest(BaseModel):
    client: Optional[str] = None
    include_dnstwist: bool = False
    include_whois: bool = True
    include_reputation: bool = True
    scope: str = "all"          # all | target | watchlist — which feed domains to scan
    variant_intel: bool = False  # gather full intel on dnstwist variants (slower, opt-in)


@router.post("/trigger", tags=["Pipeline"])
def trigger(req: TriggerRequest, background_tasks: BackgroundTasks):
    """Triggera la pipeline in background."""
    global _running, _run_started
    with _lock:
        # A pipeline is considered STALE (and force-reset) if either:
        #  - it has been running longer than the absolute max duration, or
        #  - its heartbeat has not advanced for HEARTBEAT_STALE_SEC (it died in a way
        #    that skipped the cleanup, e.g. OOM/SIGKILL/container crash).
        if _running:
            elapsed = time.time() - _run_started
            since_beat = time.time() - _last_heartbeat
            if elapsed > PIPELINE_MAX_DURATION:
                logger.warning(f"Pipeline stale (durata {elapsed:.0f}s), reset forzato")
                _running = False
            elif since_beat > HEARTBEAT_STALE_SEC:
                logger.warning(f"Pipeline stale (nessun heartbeat da {since_beat:.0f}s), reset forzato")
                _running = False
        if _running:
            since_beat = time.time() - _last_heartbeat
            return JSONResponse(status_code=409,
                                content={"error": "Pipeline già in esecuzione",
                                         "running_since": _run_started,
                                         "seconds_since_heartbeat": round(since_beat, 1)})
        _running = True
        _run_started = time.time()

    background_tasks.add_task(_run_pipeline, req)
    return {"status": "triggered", "client": req.client or "all",
            "scope": req.scope, "dnstwist": req.include_dnstwist,
            "variant_intel": req.variant_intel, "timestamp": now_iso()}


@router.post("/trigger/reset", tags=["Pipeline"])
def trigger_reset():
    """Force-release the pipeline lock.

    Escape hatch for when a pipeline died in a way that skipped cleanup (OOM /
    SIGKILL / container crash) and left `_running` stuck, blocking all new scans
    with 409. The heartbeat check in /trigger auto-recovers after HEARTBEAT_STALE_SEC,
    but this lets an operator unblock immediately without restarting the service.
    Follows the orchestrator's network-isolation model (no app-level auth; reachable
    only from the internal network / dashboard)."""
    global _running
    was_running = _running
    since_beat = time.time() - _last_heartbeat if was_running else 0
    with _lock:
        _running = False
        _progress.update({"running": False, "phase": "idle"})
    logger.warning(f"Pipeline lock reset manuale (era running={was_running}, "
                   f"ultimo heartbeat {since_beat:.0f}s fa)")
    return {"status": "reset", "was_running": was_running,
            "seconds_since_heartbeat": round(since_beat, 1), "timestamp": now_iso()}


def _module_failed(value) -> bool:
    """A module's result does not count as a valid observation when
    `_fetch_service` returned None (HTTP/transport error) or the service
    itself returned its empty-result shape with a non-empty `error` field
    (external source unavailable). CODE-01: saving either into baseline
    zeroes out the previous good state for that section.

    CODE-14: `reputation` and `http_fingerprint` never populate the
    top-level `error` field even on total failure — `collection_failed`
    (shared/utils.py) also reads their real failure shapes (nested
    per-source errors / `overall_status`), so a persistent VT/OTX/ST or
    HTTP outage no longer looks like a clean/down-but-successful result."""
    if value is None:
        return True
    return collection_failed(value)


def _build_collection_status(intel: dict, requested: set = None) -> dict:
    """CODE-15 + CODE-14 (riunificati): costruisce UNA VOLTA, qui, lo stato di
    raccolta per ciclo — {nome_sezione: bool}, True se fallita — mentre `intel`
    è ancora nella forma prodotta dai collector. Riusa `_module_failed`, lo
    stesso punto di verità del canale alert/baseline, così il classificatore
    può leggerlo dal payload invece di ri-ispezionare i dict grezzi
    (architettura B2, decisione utente 2026-08-02).

    COL-02: `dns` ora è dentro. True solo se il MODULO è fallito (`None`, oppure
    `error` valorizzato: dopo RES-01 `/dns` lo imposta quando tutti e 7 i tipi
    base sono `unknown`). Un `unknown` PARZIALE (es. SERVFAIL sul solo A) non
    rende il modulo fallito: il classificatore lo legge da `records_status` nel
    payload, così non dipende da ciò che dichiara il chiamante.

    CODE-15+CODE-14 (G3 terzo giro, requisito 1): `intel[name] is None`
    significa sia "la raccolta è stata tentata ed è fallita" SIA "la sezione
    non è stata richiesta in questo ciclo" (`include_whois=False`/
    `include_reputation=False` in `_gather_intelligence`) — due fatti diversi
    collassati nello stesso valore. `requested` è l'insieme dei nomi
    effettivamente richiesti in questo ciclo: una sezione non richiesta viene
    esclusa dal risultato invece di passare per `_module_failed(None)`, che
    non può fare questa distinzione da solo. `None` (default) preserva il
    comportamento per i chiamanti che non passano `requested` (retrocompatibile:
    tutte e cinque le sezioni valutate, `dns` compresa)."""
    names = ("whois", "cert", "http", "reputation", "dns")
    if requested is None:
        requested = set(names)
    return {name: _module_failed(intel.get(name)) for name in names if name in requested}


# SCO-05: un dominio omografo dormiente (nessun A/MX) non raggiunge mai
# `_gather_intelligence` (v. il gate `dns_a or dns_mx` nel branch dnstwist
# sotto), quindi nessuna raccolta WHOIS viene mai tentata per lui. Questa
# variabile abilita una raccolta WHOIS-only — non l'intero gather — per i
# soli nomi elencati dall'operatore, lista separata da virgole. Default
# VUOTO: nessuna chiamata WHOIS uscente in più rispetto a oggi finché non
# viene configurata. Sta in configurazione e non nel sorgente perché i nomi
# in questione sono lookalike di clienti reali e questo file è tracciato e
# pubblicabile (CLAUDE.md §2).
WHOIS_ONLY_DOMAINS = frozenset(
    d.strip().lower() for d in os.environ.get("WHOIS_ONLY_DOMAINS", "").split(",") if d.strip()
)

# SCO-05, riuso a costo zero: un WHOIS omografo già osservato in un ciclo
# precedente evita che la severità di caso oscilli fra un ciclo risolvente
# (WHOIS reale) e uno dormiente (nessun dato). Cache in-process, chiavata su
# `(client, dominio)` come `intel_store`: due tenant dello stesso MSSP che
# monitorano marchi affini incrociano gli stessi lookalike, e servire a uno il
# WHOIS raccolto per l'altro attraversa il confine di tenant.
# `OrderedDict` con tetto perché il processo gira per giorni: un dict di modulo
# senza eviction cresce quanto il numero di omografi osservati.
_HOMOGLYPH_WHOIS_CACHE = OrderedDict()
_HOMOGLYPH_WHOIS_CACHE_MAX = 512
# Soglia di freschezza del riuso. Senza scadenza, per un omografo
# PERMANENTEMENTE dormiente il WHOIS non verrebbe mai più aggiornato e
# `is_aged` resterebbe congelato su un'osservazione vecchia, disattivando
# `recently_reregistered` (classifier.py) — che esiste per rilevare un dominio
# scaduto e ri-registrato da un attaccante e confronta `updated_date` con una
# finestra di 120 giorni. La soglia sta sotto quella finestra.
_HOMOGLYPH_WHOIS_MAX_AGE_S = 30 * 86400


def _is_fresh_iso(updated_at) -> bool:
    """SCO-05: True se il timestamp ISO passato è entro
    `_HOMOGLYPH_WHOIS_MAX_AGE_S`. Un timestamp assente o illeggibile conta
    come NON fresco: di un'osservazione di cui non si può stabilire l'età non
    si può nemmeno affermare che sia ancora valida."""
    from datetime import datetime, timezone
    if not isinstance(updated_at, str):
        return False
    try:
        ts = datetime.fromisoformat(updated_at)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() <= _HOMOGLYPH_WHOIS_MAX_AGE_S


def _observation_is_fresh(observed) -> bool:
    """COL-14: True se `observed`, l'istante di un'osservazione WHOIS
    (`carried_over.observed_at` o `timestamp`), è entro `_HOMOGLYPH_WHOIS_MAX_AGE_S`.
    Diversamente da `_is_fresh_iso` un istante nel futuro NON è fresco: un'osservazione
    non può essere successiva all'adesso, e viene da uno snapshot forgiato o corrotto.
    Riusa il parse di COL-12/COL-13 (`_dns_observed_at`: confronto fra istanti, senza
    fuso vale UTC, non stringa o illeggibile = None) con l'adesso come `carried_at`;
    con una sezione fittizia prende il ramo del `timestamp` e la parte non serve,
    come in `_carry_module`."""
    return _is_fresh_iso(_dns_observed_at({"timestamp": observed}, None, now_iso()))


def _stored_whois_is_fresh(whois, updated_at) -> bool:
    """COL-14: la freschezza del WHOIS persistito si misura sull'istante in cui è stato
    OSSERVATO, non su `updated_at`: `_persist_intel` lo riscrive a ogni ciclo e, con il
    WHOIS in errore, riporta la sezione vecchia (CODE-01), quindi `updated_at` dice
    quando lo snapshot è stato salvato e non quanto è vecchio il dato. Per forma:
    - con marcatore `carried_over` valido (oggetto con `carried_at`, scritto da COL-13)
      decide solo `observed_at`; il `timestamp` accanto non lo sostituisce, perché il
      marcatore è ciò che il riporto ha scritto leggendolo. `observed_at` null = età ignota;
    - senza marcatore e con `timestamp` (anche gli snapshot riportati prima di COL-13, che
      conservano quello originale): servono `timestamp` fresco E `updated_at` fresco. Un
      `timestamp` recente in uno snapshot salvato oltre la soglia è incoerente (la sezione
      non può essere stata osservata dopo l'ultimo salvataggio) e non basta da solo;
    - senza né l'uno né l'altro decide `updated_at`, com'era (SCO-05).
    La chiave `timestamp` presente ma nulla o illeggibile non ricade su `updated_at`:
    l'istante c'è ed è ignoto, quindi non fresco."""
    is_dict = isinstance(whois, dict)
    marker = whois.get("carried_over") if is_dict else None
    if isinstance(marker, dict) and "carried_at" in marker:
        return _observation_is_fresh(marker.get("observed_at"))
    if is_dict and "timestamp" in whois:
        return _observation_is_fresh(whois["timestamp"]) and _is_fresh_iso(updated_at)
    return _is_fresh_iso(updated_at)


def _remember_homoglyph_whois(client: str, vdomain: str, whois_data):
    """SCO-05: memorizza il WHOIS osservato con l'istante dell'osservazione, ed
    espelle la voce più vecchia oltre il tetto (LRU sulla scrittura)."""
    _HOMOGLYPH_WHOIS_CACHE[(client, vdomain)] = (time.time(), whois_data)
    _HOMOGLYPH_WHOIS_CACHE.move_to_end((client, vdomain))
    while len(_HOMOGLYPH_WHOIS_CACHE) > _HOMOGLYPH_WHOIS_CACHE_MAX:
        _HOMOGLYPH_WHOIS_CACHE.popitem(last=False)


def _cached_homoglyph_whois(client: str, vdomain: str):
    """SCO-05: legge il WHOIS di un dominio omografo già noto da un ciclo
    precedente, senza tentare alcuna nuova raccolta — prima da `intel_store`
    (persistito su disco, sopravvive al riavvio del container), poi dalla cache
    in-process. Nessuna delle due fa una chiamata di rete. Entrambe le fonti
    passano dalla stessa soglia di freschezza: un'osservazione vecchia non deve
    congelare l'età del dominio (v. `_HOMOGLYPH_WHOIS_MAX_AGE_S`).
    COL-14: per lo snapshot la soglia vale sull'istante di osservazione del WHOIS e non
    solo su `updated_at`, che il riporto di un modulo in errore rinnova (v.
    `_stored_whois_is_fresh`). La cache in-process resta com'era."""
    snap = intel_store.load_snapshot(client, vdomain)
    stored_whois = ((snap or {}).get("intel") or {}).get("whois")
    if (stored_whois is not None and not _module_failed(stored_whois)
            and _stored_whois_is_fresh(stored_whois, (snap or {}).get("updated_at"))):
        return stored_whois
    cached = _HOMOGLYPH_WHOIS_CACHE.get((client, vdomain))
    if cached and (time.time() - cached[0]) <= _HOMOGLYPH_WHOIS_MAX_AGE_S:
        return cached[1]
    return None


# COL-12: le parti del `dns` che il riporto può copiare dal ciclo precedente e che quindi
# portano un marcatore in `carried_over`. Sottodomini e selettori DKIM si riportano per nome
# e il loro marcatore sta dentro la sezione (COL-31, `_carry_forward_names`).
_DNS_CARRY_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")
_DNS_CARRY_SECTIONS = ("spf", "dmarc", "bimi", "caa")


def _dns_known_parts(dns) -> set:
    """COL-12: le parti di `dns` con un valore noto (stato diverso da `unknown`; senza stato,
    com'erano gli snapshot di prima di RES-01, basta che ci sia). Solo per queste copiare il
    precedente dà un dato vecchio presentato come attuale: copiare un `unknown` non dice nulla."""
    records, email = dns.get("records"), dns.get("email_auth")
    unknown = dns_unknown_rtypes(dns)
    known = {t for t in _DNS_CARRY_TYPES
             if isinstance(records, dict) and isinstance(records.get(t), list) and t not in unknown}
    known |= {s for s in _DNS_CARRY_SECTIONS
              if isinstance(email, dict) and isinstance(email.get(s), dict)
              and email[s].get("status") != "unknown"}
    return known


def _dns_observed_at(prev_dns, part, carried_at):
    """COL-12: istante dell'ultima osservazione reale di `part`. Una parte già riportata nel
    precedente lo eredita dal suo marcatore; altrimenti era stata osservata, e vale il
    `timestamp` del precedente. Voce malformata, istante illeggibile o `timestamp` assente
    danno None (età ignota, che il classificatore conta come infinita): mai «più fresca» del
    vero. Idem un'osservazione SUCCESSIVA a `carried_at`: non può essere nel futuro del ciclo
    che la riporta (orologio di `/dns` avanti, snapshot forgiato), e con età negativa l'alert
    non uscirebbe mai. Il confronto è fra istanti, non fra stringhe; senza fuso vale UTC (come
    nel classificatore: naive e aware non si confrontano). L'istante è ri-serializzato dal
    parse, non copiato: viene da file su disco e da `/dns`, zona non autenticata."""
    from datetime import datetime, timezone
    marker = prev_dns.get("carried_over")
    if isinstance(marker, dict) and part in marker:
        entry = marker[part]
        observed = entry.get("observed_at") if isinstance(entry, dict) else None
    else:
        observed = prev_dns.get("timestamp")

    def _utc(ts):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    try:
        observed = datetime.fromisoformat(observed)
        if _utc(observed) > _utc(datetime.fromisoformat(carried_at)):
            return None
        return observed.isoformat()
    except (TypeError, ValueError):
        return None


def _dns_carried_marker(prev_dns, parts, carried_at) -> dict:
    """COL-12: `{parte: {observed_at, carried_at}}` per le `parts` riportate. Si scorre
    l'elenco fisso, non le chiavi del precedente: i nomi estranei non entrano nello snapshot."""
    return {part: {"observed_at": _dns_observed_at(prev_dns, part, carried_at), "carried_at": carried_at}
            for part in (*_DNS_CARRY_TYPES, *_DNS_CARRY_SECTIONS) if part in parts}


def _carry_forward_dns(prev_dns, dns, carried_at):
    """COL-02: la regola CODE-01 applicata PER PARTE. Un tipo di record (o SPF/DMARC/
    BIMI/CAA) che in questo ciclo è `unknown` — il DNS non ha risposto — non è
    un'osservazione: salvarlo come `[]` sovrascriverebbe la baseline sana e, al ciclo
    dopo, il valore vero comparirebbe come «aggiunto». Prende record e stato del
    precedente (precedente senza stato: record copiati, marcatore `unknown` tolto, cioè
    «noto» come per gli snapshot di prima di RES-01); senza un precedente utilizzabile
    resta `[]` con stato `unknown`: il `/diff` salta un `unknown` del ciclo corrente, ma
    lo confronta come assente se è solo nella baseline, così il primo valore noto non
    vuoto allerta come un cambio ordinario (SEC-31). Sottodomini e selettori DKIM
    non sono parti: si riportano per nome in `_carry_forward_names` (COL-31).
    Lavora su una copia profonda: `intel["dns"]` è ciò che classificazione ed eventi
    leggono dopo, e deve restare l'osservazione di QUESTO ciclo.
    COL-12: ogni parte riportata che nel precedente aveva un valore noto entra in
    `carried_over` con l'istante dell'ultima osservazione e quello di questo ciclo: senza,
    lo snapshot mostra il dato vecchio con lo stato copiato (`ok`) come se fosse di oggi."""
    if not isinstance(dns, dict):
        return dns
    if "carried_over" in dns:
        # COL-12: il marcatore lo scrive solo l'orchestrator; uno arrivato da `/dns` (zona
        # non autenticata) non entra nello snapshot.
        dns = {k: v for k, v in dns.items() if k != "carried_over"}
    unknown = dns_unknown_rtypes(dns)
    email = dns.get("email_auth")
    sections = [s for s in ("spf", "dmarc", "bimi", "caa")
                if isinstance(email, dict) and isinstance(email.get(s), dict)
                and email[s].get("status") == "unknown"]
    if not unknown and not sections:
        return dns
    out = copy.deepcopy(dns)
    prev_dns = prev_dns if isinstance(prev_dns, dict) else {}
    prev_records, prev_status = prev_dns.get("records"), prev_dns.get("records_status")
    carried = set()
    if isinstance(out.get("records"), dict) and isinstance(prev_records, dict):
        for rtype in unknown:
            if not isinstance(prev_records.get(rtype), list):
                continue
            out["records"][rtype] = copy.deepcopy(prev_records[rtype])
            carried.add(rtype)
            if isinstance(prev_status, dict) and rtype in prev_status:
                out["records_status"][rtype] = copy.deepcopy(prev_status[rtype])
            else:
                del out["records_status"][rtype]
    prev_email = prev_dns.get("email_auth")
    if isinstance(prev_email, dict):
        for section in sections:
            if isinstance(prev_email.get(section), dict):
                out["email_auth"][section] = copy.deepcopy(prev_email[section])
                carried.add(section)
    marker = _dns_carried_marker(prev_dns, carried & _dns_known_parts(prev_dns), carried_at)
    if marker:
        out["carried_over"] = marker
    return out


def _dns_name_sections(dns):
    """COL-31: le sezioni `subdomains` ed `email_auth.dkim` di `dns`, None dove non c'è un dict.
    Arrivano da `/dns` (zona non autenticata) e da disco: una forma diversa non ha nomi da riportare."""
    email = dns.get("email_auth") if isinstance(dns, dict) else None
    subs = dns.get("subdomains") if isinstance(dns, dict) else None
    dkim = email.get("dkim") if isinstance(email, dict) else None
    return (subs if isinstance(subs, dict) else None), (dkim if isinstance(dkim, dict) else None)


def _has_lists(section, *keys):
    return isinstance(section, dict) and all(isinstance(section.get(key), list) for key in keys)


def _in_list_order(listed, fresh, carried, name):
    """COL-31: gli elementi del ciclo (`fresh`) e i riportati (`carried`, per nome) nella posizione del
    loro nome in `listed`, l'ordine in cui `/dns` li produce: messi in coda, la vista cambierebbe ordine
    a ogni taglio. Gli elementi del ciclo con un nome fuori elenco restano, in fondo."""
    out = []
    for n in listed:
        out += [carried[n]] if n in carried else [x for x in fresh if name(x) == n]
    return out + [x for x in fresh if name(x) not in listed]


def _with_name_markers(dns, prev_dns, subdomains, selectors, carried_at):
    """COL-31: copia di `dns` con `subdomains.carried_over` ed `email_auth.dkim.carried_over` =
    `{nome: {observed_at, carried_at}}` sui soli nomi riportati, e senza la chiave dove non ce ne sono.
    Il marcatore lo scrive solo l'orchestrator: uno arrivato da `/dns` (zona non autenticata) cade, e
    quello della sezione precedente non si copia ma si ricostruisce. Sta dentro la sezione perché
    classificatore e dashboard leggono `dns.carried_over` sull'elenco fisso delle 11 parti.
    `observed_at` con le regole di `_dns_observed_at`, su una sezione fittizia come in COL-16: la voce
    del nome nel marcatore della sezione precedente, altrimenti il `timestamp` del precedente.
    Copie superficiali: `dns` è l'osservazione del ciclo o la sezione su disco, e non si modifica."""
    (subs, dkim), (prev_subs, prev_dkim) = _dns_name_sections(dns), _dns_name_sections(prev_dns)

    def _marked(section, prev_section, names):
        out = {k: v for k, v in section.items() if k != "carried_over"}
        if names:
            holder = {"carried_over": (prev_section or {}).get("carried_over"), "timestamp": prev_dns.get("timestamp")}
            out["carried_over"] = {n: {"observed_at": _dns_observed_at(holder, n, carried_at),
                                       "carried_at": carried_at} for n in names}
        return out

    out = dict(dns)
    if subs is not None:
        out["subdomains"] = _marked(subs, prev_subs, subdomains)
    if dkim is not None:
        out["email_auth"] = {**dns["email_auth"], "dkim": _marked(dkim, prev_dkim, selectors)}
    return out


def _carry_forward_names(prev_dns, dns, domain, carried_at):
    """COL-31: la regola di COL-02 per nome, per i sottodomini e i selettori DKIM. `/dns` prova uno per
    uno un elenco fisso di nomi: uno senza risposta (anche perché la scadenza complessiva della
    richiesta ha tagliato il suo stadio) va in `subdomains.unknown` o in `dkim.selectors_unknown`, manca
    da `active`/`selectors_found` e, salvato così, sparirebbe dallo snapshot per il solo silenzio del
    DNS. Un nome dell'elenco senza risposta che nel precedente era attivo (o trovato, con i suoi record)
    resta con il dato precedente, nella sua posizione, e con una voce nel marcatore di sezione.
    `unknown` e `selectors_unknown` restano quelli del ciclo: dicono che il nome non è stato determinato,
    il marcatore l'istante della sua ultima osservazione. Un nome che ha risposto `nxdomain`/`nodata` non è in
    `unknown` e sparisce. Nessuna scadenza, come per i tipi base: una soglia darebbe a chi controlla il
    DNS la leva di restare muto oltre. Gli alert non cambiano, e una regola che confrontasse i selettori
    trovati non vedrebbe un selettore «aggiunto» al ritorno da ogni taglio. Si scorre l'elenco fisso per
    il `domain` del ciclo, non le liste ricevute da `/dns` (zona non autenticata) e da disco: con liste
    malformate non si riporta nulla. Senza copia profonda, come la sezione intera di COL-13: il dato
    precedente viene da disco e non si modifica, e `copy.deepcopy` solleverebbe su un valore annidato
    oltre il suo limite, che `json` carica, facendo saltare il salvataggio dello snapshot."""
    if not isinstance(dns, dict):
        return dns
    prev_dns = prev_dns if isinstance(prev_dns, dict) else {}
    (subs, dkim), (prev_subs, prev_dkim) = _dns_name_sections(dns), _dns_name_sections(prev_dns)
    out, carried_subs, carried_sels = dict(dns), {}, {}
    if _has_lists(subs, "active", "unknown") and _has_lists(prev_subs, "active"):
        listed = [f"{s}.{domain}" for s in DEFAULT_SUBDOMAINS]
        prev = {e["fqdn"]: e for e in prev_subs["active"] if isinstance(e, dict) and isinstance(e.get("fqdn"), str)}
        fresh = [e.get("fqdn") for e in subs["active"] if isinstance(e, dict)]
        carried_subs = {n: prev[n] for n in listed if n in subs["unknown"] and n in prev and n not in fresh}
        if carried_subs:
            out["subdomains"] = {**subs, "active": _in_list_order(
                listed, subs["active"], carried_subs, lambda e: e.get("fqdn") if isinstance(e, dict) else None)}
    if (_has_lists(dkim, "selectors_found", "selectors_unknown") and isinstance(dkim.get("records"), dict)
            and _has_lists(prev_dkim, "selectors_found") and isinstance(prev_dkim.get("records"), dict)):
        carried_sels = {s: prev_dkim["records"][s] for s in DEFAULT_DKIM_SELECTORS
                        if s in dkim["selectors_unknown"] and s not in dkim["selectors_found"]
                        and s in prev_dkim["selectors_found"] and isinstance(prev_dkim["records"].get(s), list)}
        if carried_sels:
            out["email_auth"] = {**dns["email_auth"], "dkim": {
                **dkim, "records": {**dkim["records"], **carried_sels},
                "selectors_found": _in_list_order(DEFAULT_DKIM_SELECTORS, dkim["selectors_found"],
                                                  {s: s for s in carried_sels}, lambda s: s)}}
    return _with_name_markers(out, prev_dns, carried_subs, carried_sels, carried_at)


def _mark_kept_names(section, carried_at):
    """COL-31: nel guasto totale con un precedente (CODE-01) resta la sezione precedente intera, nomi
    compresi: ogni sottodominio attivo e ogni selettore trovato è riportato, e il marcatore di sezione,
    ricostruito su questi nomi, lo dice. Senza, lo snapshot li presenta come osservati nel ciclo."""
    subs, dkim = _dns_name_sections(section)
    fqdns = [e.get("fqdn") for e in subs["active"] if isinstance(e, dict)] if _has_lists(subs, "active") else []
    found = dkim["selectors_found"] if _has_lists(dkim, "selectors_found") else []
    return _with_name_markers(section, section, [n for n in fqdns if isinstance(n, str)],
                              [s for s in found if isinstance(s, str)], carried_at)


def _carry_module(prev_section, carried_at):
    """COL-13: la regola CODE-01 per un modulo intero (cert, whois, http, reputation) fallito:
    resta la sezione precedente, con `carried_over = {observed_at, carried_at}`. Senza,
    lo snapshot mostra il dato vecchio come attuale: `updated_at` si rinnova a ogni salvataggio
    e il report dice «ok». Campo diretto e non una mappa come nel DNS: il modulo non ha parti.
    Una precedente che non è un dict, o che è già un fallimento, resta com'è e senza marcatore:
    non c'è un dato da dichiarare riportato. La dashboard la legge «errore» solo per le forme
    con `error` di primo livello (cert, whois); http e reputation già falliti non lo hanno
    (CODE-14), quindi in uno snapshot salvato prima di CODE-14 la legge «ok».
    Il marcatore vecchio non si eredita: `observed_at` è il `timestamp` della sezione, che il
    riporto non rinnova. `_dns_observed_at` lo legge e lo ri-serializza con le regole del DNS
    (confronto fra istanti, senza fuso vale UTC, mai nel futuro del ciclo); passandole la
    sezione già senza marcatore prende il ramo del `timestamp`, e la parte non serve.
    Copia superficiale: la precedente viene da disco e non si tocca."""
    if not isinstance(prev_section, dict):
        return prev_section
    try:
        if _module_failed(prev_section):
            return prev_section
    except TypeError:
        # CODE-49: `collection_failed` solleva su `checks` non iterabile (file corrotto, risposta
        # forgiata). Non è un fallimento riconoscibile: si riporta e si marca come le altre,
        # invece di far saltare il salvataggio dello snapshot a ogni ciclo.
        pass
    section = {k: v for k, v in prev_section.items() if k != "carried_over"}
    section["carried_over"] = {"observed_at": _dns_observed_at(section, None, carried_at),
                               "carried_at": carried_at}
    return section


# COL-16: le fonti della sezione `reputation` che il riporto può copiare dal ciclo precedente.
_REPUTATION_SOURCES = ("virustotal", "otx", "securitytrails")


def _carry_reputation_sources(prev_rep, rep, carried_at):
    """COL-16: la regola CODE-01 applicata PER FONTE alla sezione `reputation` di un ciclo in cui il
    modulo ha risposto (se ha fallito per intero decide `_carry_module`). `collection_failed` lo
    dichiara fallito solo con TUTTE le fonti in errore (CODE-14): con una sola guasta la sezione si
    salverebbe com'è, con la fonte a zero, e al ritorno della fonte il valore vero comparirebbe come
    «nuovo» (`vt_malicious_detected` CRITICAL per un valore osservato prima del guasto). Una
    fonte non osservata (`reputation_source_unobserved`) che nel precedente risulta osservata, 404 di VT
    compreso, resta quella precedente, con `carried_sources = {fonte: {observed_at, carried_at}}`.
    `observed_at` è quello del marcatore precedente per la fonte, altrimenti il `timestamp` della
    sezione precedente (una fonte senza marcatore è stata osservata in quel ciclo). Stesso parse di COL-12
    (`_dns_observed_at`) su una sezione fittizia, come in `_carry_module`: istante illeggibile o
    successivo al ciclo = None, e il marcatore precedente non si copia ma si ricostruisce. Una fonte
    `None` (non interrogata) o senza un precedente osservato resta com'è e non ferma le altre.
    Il `timestamp` della sezione è quello del ciclo: le fonti che hanno risposto sono di QUESTO ciclo.
    Con almeno una fonte riportata `risk_score`/`risk_level` si ricalcolano sulla sezione salvata:
    `_calc_score` esclude le fonti in errore, quindi quelli del ciclo guasto abbasserebbero il
    rischio persistito. Un `carried_sources` arrivato da `/reputation` (zona non autenticata) non
    entra nello snapshot: lo scrive solo questo orchestrator.
    Copie: `intel["reputation"]` è l'osservazione di QUESTO ciclo, letta poi da eventi e
    classificazione; la precedente viene da disco."""
    if not isinstance(rep, dict):
        return rep
    if "carried_sources" in rep:
        rep = {k: v for k, v in rep.items() if k != "carried_sources"}
    if not isinstance(prev_rep, dict):
        return rep
    try:
        carried = {source: copy.deepcopy(prev_rep[source]) for source in _REPUTATION_SOURCES
                   if reputation_source_unobserved(rep.get(source))
                   and isinstance(prev_rep.get(source), dict)
                   and not reputation_source_unobserved(prev_rep[source])}
        if not carried:
            return rep
        prev_marker = {"carried_over": prev_rep.get("carried_sources"), "timestamp": prev_rep.get("timestamp")}
        out = {**rep, **carried}
        out["carried_sources"] = {source: {"observed_at": _dns_observed_at(prev_marker, source, carried_at),
                                           "carried_at": carried_at} for source in carried}
        out["risk_score"] = _calc_score(out)
        out["risk_level"] = _score_to_level(out["risk_score"])
    except (TypeError, AttributeError, ArithmeticError, RecursionError) as e:
        # Come la guardia di `_carry_module`: la sezione precedente viene da disco e quella del ciclo da
        # `/reputation` (zona non autenticata). Con dati non validi (numeri non numerici, una fonte
        # annidata oltre il limite di `copy.deepcopy`) riporto, marcatore e ricalcolo sollevano, e
        # `_persist_intel` propaga: il salvataggio dello snapshot salta, nel ramo varianti salta anche la
        # classificazione, e uno snapshot avvelenato su disco verrebbe riportato a ogni ciclo con la fonte
        # in errore. Si ricade sulla sezione del ciclo com'è, senza marcatori in ingresso: nessun riporto,
        # lo snapshot si salva e quello avvelenato si sostituisce al primo ciclo.
        # `ArithmeticError` perché `_calc_score` solleva `OverflowError` con un float non finito più un
        # intero enorme, entrambi validi in JSON. Il log riporta solo la classe: la sezione contiene valori
        # del payload, che arriva da una zona non autenticata, e `str(e)` può contenerne.
        logger.warning(f"  reputation: riporto per fonte non applicato ({type(e).__name__})")
        return rep
    return out


# COL-02: i quattro stati che `dig_lookup` produce. Un valore diverso in `records_status`
# non arriva dai byte DNS ma da un payload forgiato o corrotto: non finisce verbatim
# in un evento verso SIEM/SOAR, vale «non dichiarato».
_DNS_STATUSES = ("ok", "nodata", "nxdomain", "unknown")


def _dns_status(dns, rtype):
    """COL-02: stato (`ok`/`nodata`/`nxdomain`/`unknown`) di un tipo nel `dns` di QUESTO
    ciclo, per gli eventi. Sezione `None` (modulo non risposto): `unknown`. Stato assente
    (`/dns` di prima di RES-01) o fuori dai quattro valori: `None`, cioè «non dichiarato»."""
    if dns is None:
        return "unknown"
    status = dns.get("records_status") if isinstance(dns, dict) else None
    value = status.get(rtype) if isinstance(status, dict) else None
    return value if value in _DNS_STATUSES else None


def _persist_intel(client: str, domain: str, legitimate: str, intel: dict):
    """
    Diff the current intel against the stored snapshot, then persist:
    save the new snapshot (overwrite) and append the diff to history (deltas only).
    Uses the classifier's /diff endpoint for the comparison.
    """
    prev = intel_store.load_snapshot(client, domain)
    prev_intel = (prev or {}).get("intel") if prev else None

    # Build the comparable intel object (exclude classification — that's separate).
    # A module that failed or errored must NOT overwrite a healthy baseline:
    # keep the previous observation for that section instead. Otherwise the
    # cycle OK -> FAILED (baseline zeroed) -> OK reports a delta equal to the
    # entire history instead of the real change (CODE-01).
    current = {}
    for name in ("dns", "cert", "http", "whois", "reputation"):
        value = intel.get(name)
        current[name] = (prev_intel or {}).get(name) if _module_failed(value) else value
    # COL-02: la stessa regola, per parte, quando il modulo ha risposto ma alcuni tipi no.
    dns = intel.get("dns")
    # COL-12: l'istante del ciclo si legge una volta, così tutte le parti riportate lo condividono.
    carried_at = now_iso()
    # COL-13: i moduli interi, con lo stesso istante del ciclo. Un `carried_over` arrivato dal
    # servizio (zona non autenticata) non entra nello snapshot: lo scrive solo questo orchestrator.
    # Copia: `intel[name]` è l'osservazione di QUESTO ciclo, letta poi da eventi e classificazione.
    for name in ("cert", "http", "whois", "reputation"):
        if _module_failed(intel.get(name)):
            current[name] = _carry_module(current[name], carried_at)
        elif isinstance(current[name], dict) and "carried_over" in current[name]:
            current[name] = {k: v for k, v in current[name].items() if k != "carried_over"}
    # COL-16: la stessa regola per fonte, quando la reputazione ha risposto ma una fonte no. Con
    # lo stesso istante del ciclo di COL-12/COL-13; il guasto di tutto il modulo lo decide
    # `_carry_module` sopra, e conserva il `carried_sources` della sezione riportata.
    if not _module_failed(intel.get("reputation")):
        current["reputation"] = _carry_reputation_sources(
            (prev_intel or {}).get("reputation"), current["reputation"], carried_at)
    if not _module_failed(dns):
        current["dns"] = _carry_forward_dns((prev_intel or {}).get("dns"), current["dns"], carried_at)
        # COL-31: poi sottodomini e selettori DKIM, per nome. L'elenco si costruisce sul dominio
        # dell'argomento, non su quello della risposta, che viene da `/dns` (zona non autenticata).
        current["dns"] = _carry_forward_names((prev_intel or {}).get("dns"), current["dns"], domain, carried_at)
    elif not isinstance(current["dns"], dict) and dns_unknown_rtypes(dns):
        # Guasto totale e nessun precedente utilizzabile (SEC-31): salvare `None` toglieva ogni
        # baseline, e al ciclo dopo il risveglio del dominio (A, MX, NS che compaiono) non
        # produceva alert. La sezione guasta porta i suoi `records_status` tutti `unknown`:
        # il `/diff` la legge come «mai noto» e allerta sul primo valore noto non vuoto, mai
        # sul vuoto. Solo per `dns`: per gli altri moduli un `[]`/`0` salvato azzererebbe il
        # riferimento («25 certificati nuovi»). Con un precedente noto resta il percorso CODE-01.
        # COL-12: senza il marcatore eventualmente arrivato da `/dns` (zona non autenticata):
        # lo scrive solo questo orchestrator. Copia: `intel["dns"]` resta l'osservazione del ciclo.
        # COL-31: idem per i marcatori di sezione di sottodomini e DKIM; nessun nome da riportare.
        current["dns"] = _with_name_markers({k: v for k, v in dns.items() if k != "carried_over"}, {}, (), (),
                                            carried_at)
    elif isinstance(current["dns"], dict):
        # COL-12: guasto totale con un precedente (CODE-01): resta la sezione precedente intera,
        # con un marcatore su ogni parte che lì aveva un valore noto. Il marcatore precedente non
        # si copia ma si ricostruisce: `carried_at` è quello di questo ciclo e i nomi estranei cadono.
        prev_dns = {k: v for k, v in current["dns"].items() if k != "carried_over"}
        marker = _dns_carried_marker(current["dns"], _dns_known_parts(current["dns"]), carried_at)
        current["dns"] = _mark_kept_names({**prev_dns, "carried_over": marker} if marker else prev_dns, carried_at)

    # Only diff if we have a previous snapshot to compare against
    if prev_intel:
        try:
            dr = _session.post(f"{CLASSIFY_URL}/diff", json={
                "domain": domain, "client": client, "legitimate": legitimate,
                "baseline": prev_intel, "current": current,
            }, timeout=15)
            if dr.ok:
                diff = dr.json()
                if intel_store.append_history(client, domain, diff):
                    logger.info(f"  intel diff: {diff.get('alert_count',0)} change(s) — {sanitize_log_input(diff.get('max_severity','CLEAN'))}")
            else:
                # CODE-43: prima solo le eccezioni lasciavano traccia, un errore HTTP no.
                logger.warning(f"  diff error: {sanitize_log_input(domain)} HTTP {dr.status_code}")
        except Exception as e:
            logger.warning(f"  diff error: {sanitize_log_input(str(e))}")

    intel_store.save_snapshot(client, domain, current)


def _ingest_cases(events: list):
    """
    Push pipeline events to the case-manager as cases (opt-in).
    Each event's classification becomes a case keyed by (domain, client).
    The case-manager handles create/update/reopen logic. Fail-safe: a failure
    here is logged but never breaks the pipeline.
    """
    if not CASE_INGEST_TOKEN:
        logger.warning("CASE_INGEST enabled but CASE_INGEST_TOKEN missing — skipping case ingest")
        return
    headers = {"Authorization": f"Bearer {CASE_INGEST_TOKEN}"}
    ok = 0
    for ev in events:
        # NRM-03: il dominio legittimo del cliente è anche un target del feed
        # (onboarding standard: lo è nella maggior parte dei feed) e viene comunque
        # scansionato e classificato — il monitoraggio resta attivo. Non deve
        # però diventare un caso di typosquatting su se stesso.
        legitimate = ev.get("legitimate")
        if legitimate and ev.get("domain") == legitimate:
            continue
        cls = ev.get("classification") or {}
        category = cls.get("auto_classification", "needs_review")
        payload = {
            "domain": ev.get("domain"),
            "client": ev.get("client"),
            "classification": category,
            "confidence": cls.get("confidence"),
            "severity": CLASSIFICATION_SEVERITY.get(category, "MEDIUM"),
            "rationale": cls.get("rationale"),
        }
        try:
            r = _session.post(f"{CASE_MANAGER_URL}/cases/ingest",
                              json=payload, headers=headers, timeout=10)
            if r.ok:
                ok += 1
            elif r.status_code in (401, 403):
                logger.error(f"Case ingest auth failed (HTTP {r.status_code}) — check CASE_INGEST_TOKEN/permissions")
                return  # token bad for all; stop early
        except Exception as e:
            logger.warning(f"Case ingest error for {ev.get('domain')}: {sanitize_log_input(str(e))}")
    logger.info(f"Case ingest: {ok}/{len(events)} events → cases")


def _run_pipeline(req: TriggerRequest):
    global _running
    _running = True
    start = time.time()
    _progress_reset(req.client, 0)

    # CODE-15+CODE-14 (G3 terzo giro, requisito 1): dns/cert/http sono richiesti
    # incondizionatamente da `_gather_intelligence`; whois/reputation dipendono
    # dai flag dell'operatore per questo ciclo. Calcolato una volta, riusato da
    # entrambe le chiamate a `_build_collection_status` sotto (ciclo principale
    # e variant_intel di dnstwist), stesso `req`.
    requested_modules = {"dns", "cert", "http"}
    if req.include_whois:
        requested_modules.add("whois")
    if req.include_reputation:
        requested_modules.add("reputation")

    try:
        # 1. Leggi feed
        feed_url = f"{FEED_URL}/feed/domains"
        if req.client:
            feed_url += f"?client={req.client}"
        r = _session.get(feed_url, timeout=10)
        r.raise_for_status()
        domains = r.json().get("domains", [])
        # Scope filter: restrict to target-only or watchlist-only if requested
        scope = (req.scope or "all").lower()
        if scope in ("target", "watchlist"):
            domains = [d for d in domains if d.get("type", "target") == scope]
            _plog(f"Scope '{scope}': {len(domains)} domini dopo il filtro")

        _plog(f"Pipeline: {len(domains)} domini da processare")
        _progress_set(total=len(domains), phase="scanning")

        # Raggruppa per client
        by_client = {}
        for d in domains:
            c = d.get("client", "unknown")
            by_client.setdefault(c, []).append(d)

        all_events = []

        for client, client_domains in by_client.items():
            _plog(f"━━ Client: {client} ({len(client_domains)} domini) ━━")
            _progress_set(client=client)

            # Carica whitelist
            try:
                wr = _session.get(f"{FEED_URL}/feed/whitelist?client={client}", timeout=5)
                whitelist = list(wr.json().get("whitelist", {}).keys()) if wr.ok else []
            except Exception:
                whitelist = []

            for entry in client_domains:
                domain = entry["domain"]
                if domain in whitelist:
                    _plog(f"  {domain} — whitelisted, skip")
                    with _lock:
                        _progress["done"] += 1
                    continue

                _plog(f"  [CHECK] {domain}")
                _progress_set(current_domain=domain)
                intel = _gather_intelligence(domain, req)

                # Classify
                try:
                    cr = _session.post(f"{CLASSIFY_URL}/classify/variant", json={
                        "domain": domain, "fuzzer": entry.get("fuzzer", ""),
                        "dns": intel.get("dns"), "cert": intel.get("cert"),
                        "http": intel.get("http"), "whois": intel.get("whois"),
                        "reputation": intel.get("reputation"),
                        "collection_status": _build_collection_status(intel, requested_modules),
                    }, timeout=10)
                    intel["classification"] = cr.json() if cr.ok else None
                except Exception as e:
                    logger.error(f"  Classification error: {e}")
                    intel["classification"] = None

                # Persist full intel snapshot + baseline diff history (opt-in).
                # Fail-safe: storage/diff errors never break the pipeline.
                if INTEL_STORE:
                    try:
                        _persist_intel(client, domain, entry.get("legitimate", domain), intel)
                    except Exception as e:
                        logger.warning(f"  intel persist error: {sanitize_log_input(str(e))}")

                # Raccogli eventi
                if intel.get("classification"):
                    all_events.append({
                        "client": client, "domain": domain,
                        "legitimate": entry.get("legitimate", domain),
                        "classification": intel["classification"],
                        "intel_summary": {
                            "dns_a": bool((intel.get("dns") or {}).get("records", {}).get("A")),
                            "dns_mx": bool((intel.get("dns") or {}).get("records", {}).get("MX")),
                            # COL-02: `dns_a`/`dns_mx` dicono «record visto in questo ciclo» e
                            # restano bool (contratto verso SIEM/SOAR); lo stato distingue
                            # «assente» da «il DNS non ha risposto».
                            "dns_a_status": _dns_status(intel.get("dns"), "A"),
                            "dns_mx_status": _dns_status(intel.get("dns"), "MX"),
                            "http_active": (intel.get("http") or {}).get("overall_status") == "active",
                            "cert_count": (intel.get("cert") or {}).get("ct_certificates", {}).get("total", 0),
                            "reputation_score": (intel.get("reputation") or {}).get("risk_score", 0),
                        }
                    })

                with _lock:
                    _progress["done"] += 1

            # dnstwist (opzionale)
            if req.include_dnstwist:
                _progress_set(phase="dnstwist", current_domain=None)
                # Run dnstwist once per DISTINCT legitimate domain, not once per
                # target: multiple targets of the same client typically share the
                # same legitimate (e.g. three targets all map to brand.example),
                # and dnstwist on the same legit yields identical variants — running
                # it per-target would repeat the whole discovery + variant-intel pass
                # N times (wasted work and external API calls).
                legits = []
                seen_legit = set()
                for d in client_domains:
                    if d.get("type") != "target":
                        continue
                    lg = d.get("legitimate", d["domain"])
                    if lg not in seen_legit:
                        seen_legit.add(lg)
                        legits.append(lg)
                for legit in legits:
                    _plog(f"  [TWIST] {legit}")
                    try:
                        tr = _session.get(f"{TWIST_URL}/twist?domain={quote(legit, safe='')}", timeout=300)
                        if tr.ok:
                            twist_data = tr.json()
                            variant_count = twist_data.get('registered_variants', 0)
                            logger.info(f"  [TWIST] {variant_count} varianti")
                            # Aggiungi ogni nuova variante come evento
                            for variant in twist_data.get("variants", []):
                                vdomain = variant.get("domain", "")
                                event = {
                                    "client": client,
                                    "domain": vdomain,
                                    "event_type": "dnstwist_variant_found",
                                    "classification": {
                                        "auto_classification": "needs_review",
                                        "rule": "dnstwist_discovery",
                                        "confidence": "low",
                                        "rationale": f"Variante {variant.get('fuzzer','')} di {legit}"
                                    },
                                    "intel_summary": {
                                        "dns_a": bool(variant.get("dns_a")),
                                        "dns_mx": bool(variant.get("dns_mx")),
                                        "fuzzer": variant.get("fuzzer", ""),
                                        "geoip": variant.get("geoip", ""),
                                    }
                                }

                                # Opt-in: gather FULL intel for registered variants so they
                                # can be triaged (tp/fp) on real data, not just the name.
                                # Only variants that resolve (A or MX) are worth the heavy
                                # pass; unregistered permutations are skipped.
                                if req.variant_intel and vdomain and (variant.get("dns_a") or variant.get("dns_mx")):
                                    logger.info(f"    [TWIST-INTEL] {sanitize_log_input(vdomain)}")
                                    try:
                                        vintel = _gather_intelligence(vdomain, req)
                                        # OPS-06: lo stesso flag del ciclo dei domini del feed.
                                        if INTEL_STORE:
                                            _persist_intel(client, vdomain, legit, vintel)
                                        # SCO-05: ricorda l'ultimo WHOIS valido di un omografo
                                        # risolvente, per riusarlo (costo zero) se lo stesso
                                        # dominio torna dormiente in un ciclo successivo — v.
                                        # `_cached_homoglyph_whois` e il ramo sotto.
                                        if (variant.get("fuzzer") == "homoglyph"
                                                and not _module_failed(vintel.get("whois"))):
                                            _remember_homoglyph_whois(client, vdomain,
                                                                      vintel.get("whois"))
                                        # Surface key signals in the event summary too
                                        vdns = (vintel.get("dns") or {}).get("records", {})
                                        vhttp = vintel.get("http") or {}
                                        vcert = (vintel.get("cert") or {}).get("ct_certificates", {})
                                        event["intel_summary"].update({
                                            "dns_a": bool(vdns.get("A")),
                                            "dns_mx": bool(vdns.get("MX")),
                                            "dns_a_status": _dns_status(vintel.get("dns"), "A"),
                                            "dns_mx_status": _dns_status(vintel.get("dns"), "MX"),
                                            "http_active": vhttp.get("overall_status") == "active",
                                            "cert_count": vcert.get("total", 0),
                                            "intel_collected": True,
                                        })
                                        # Now that we have real intel (incl. WHOIS), let the
                                        # classifier decide instead of leaving the placeholder
                                        # "needs_review" from discovery. This is what applies the
                                        # domain-age rule and the parking/for-sale/threat rules to
                                        # dnstwist variants.
                                        try:
                                            vcr = _session.post(f"{CLASSIFY_URL}/classify/variant", json={
                                                "domain": vdomain,
                                                "fuzzer": variant.get("fuzzer", ""),
                                                "dns": vintel.get("dns"), "cert": vintel.get("cert"),
                                                "http": vintel.get("http"), "whois": vintel.get("whois"),
                                                "reputation": vintel.get("reputation"),
                                                "collection_status": _build_collection_status(vintel, requested_modules),
                                            }, timeout=TIMEOUT)
                                            if vcr.ok:
                                                vcls = vcr.json()
                                                event["classification"] = {
                                                    "auto_classification": vcls.get("auto_classification", "needs_review"),
                                                    "rule": vcls.get("rule", "dnstwist_discovery"),
                                                    "confidence": vcls.get("confidence", "low"),
                                                    "rationale": vcls.get("rationale") or
                                                                 f"Variante {variant.get('fuzzer','')} di {legit}",
                                                }
                                        except Exception as e:
                                            logger.warning(f"    [TWIST-CLASSIFY] {sanitize_log_input(vdomain)} "
                                                           f"error: {sanitize_log_input(str(e))}")
                                    except Exception as e:
                                        logger.warning(f"    [TWIST-INTEL] {sanitize_log_input(vdomain)} error: {sanitize_log_input(str(e))}")

                                elif req.variant_intel and vdomain and variant.get("fuzzer") == "homoglyph":
                                    # SCO-05: un omografo dormiente non soddisfa il gate sopra e
                                    # resterebbe bloccato a tempo indefinito sul placeholder di
                                    # discovery. La mescolanza di script è un'osservazione del
                                    # solo NOME e non richiede alcuna raccolta, quindi la variante
                                    # va comunque classificata. Il WHOIS, se esiste, arriva a costo
                                    # zero da un ciclo precedente (snapshot persistito o cache);
                                    # una raccolta WHOIS-only dal vivo è tentata solo per i domini
                                    # configurati in `WHOIS_ONLY_DOMAINS` e solo se il ciclo
                                    # include il WHOIS — mai l'intero gather.
                                    whois_data = _cached_homoglyph_whois(client, vdomain)
                                    # `_build_collection_status` (sopra) dichiara una sezione solo
                                    # se è stata parte del ciclo: qui la chiave `whois` compare
                                    # unicamente quando una raccolta è stata davvero tentata, così
                                    # "mai tentato" non viene confuso con "tentato e fallito" e un
                                    # ciclo con `include_whois=False` non si vede dichiarare lo
                                    # stato di una sezione che non ha richiesto.
                                    collection_status = {}
                                    if (whois_data is None and req.include_whois
                                            and vdomain.lower() in WHOIS_ONLY_DOMAINS):
                                        logger.info(f"    [TWIST-WHOIS-ONLY] {sanitize_log_input(vdomain)}")
                                        _, whois_data = _fetch_service(
                                            "whois", f"{WHOIS_URL}/whois?domain={quote(vdomain, safe='')}")
                                        collection_status = {"whois": _module_failed(whois_data)}
                                        if not collection_status["whois"]:
                                            _remember_homoglyph_whois(client, vdomain, whois_data)

                                    try:
                                        vcr = _session.post(f"{CLASSIFY_URL}/classify/variant", json={
                                            "domain": vdomain,
                                            "fuzzer": variant.get("fuzzer", ""),
                                            "whois": whois_data,
                                            "collection_status": collection_status,
                                        }, timeout=TIMEOUT)
                                        if vcr.ok:
                                            vcls = vcr.json()
                                            event["classification"] = {
                                                "auto_classification": vcls.get("auto_classification", "needs_review"),
                                                "rule": vcls.get("rule", "dnstwist_discovery"),
                                                "confidence": vcls.get("confidence", "low"),
                                                "rationale": vcls.get("rationale") or
                                                             f"Variante {variant.get('fuzzer','')} di {legit}",
                                            }
                                    except Exception as e:
                                        logger.warning(f"    [TWIST-WHOIS-ONLY] {sanitize_log_input(vdomain)} "
                                                       f"error: {sanitize_log_input(str(e))}")

                                elif vdomain:
                                    # CODE-17: senza intel la variante passa comunque dal classificatore, col solo
                                    # nome: le regole sul nome (omografi) valgono anche qui. Nessun modulo è
                                    # dichiarato, quindi niente di non raccolto viene letto come assente. Per un
                                    # omografo il WHOIS già noto (SCO-05, nessuna chiamata di rete), così un dominio
                                    # vecchio non diventa HIGH solo perché questo ciclo non raccoglie. Se il
                                    # classificatore non risponde resta il segnaposto di discovery; la scadenza è
                                    # quella della classificazione dei domini del feed, una chiamata per variante.
                                    whois_data = (_cached_homoglyph_whois(client, vdomain)
                                                  if variant.get("fuzzer") == "homoglyph" else None)
                                    try:
                                        vcr = _session.post(f"{CLASSIFY_URL}/classify/variant", json={
                                            "domain": vdomain,
                                            "fuzzer": variant.get("fuzzer", ""),
                                            "whois": whois_data,
                                            "collection_status": {},
                                        }, timeout=10)
                                        if vcr.ok:
                                            vcls = vcr.json()
                                            event["classification"] = {
                                                "auto_classification": vcls.get("auto_classification", "needs_review"),
                                                "rule": vcls.get("rule", "dnstwist_discovery"),
                                                "confidence": vcls.get("confidence", "low"),
                                                "rationale": vcls.get("rationale") or
                                                             f"Variante {variant.get('fuzzer','')} di {legit}",
                                            }
                                    except Exception as e:
                                        logger.warning(f"    [TWIST-CLASSIFY] {sanitize_log_input(vdomain)} "
                                                       f"error: {sanitize_log_input(str(e))}")

                                all_events.append(event)
                    except Exception as e:
                        logger.error(f"  dnstwist error: {e}")

        # Pubblica eventi
        if all_events:
            try:
                _session.post(f"{EVENT_URL}/publish", json={"events": all_events}, timeout=10)
                _plog(f"Pubblicati {len(all_events)} eventi")
            except Exception as e:
                logger.error(f"Event publish error: {e}")

            # Ingest automatico nei case (opt-in via CASE_INGEST=true).
            # Trasforma ogni evento in un case gestibile dal case-manager.
            # Fail-safe: un errore qui non compromette la pipeline.
            if CASE_INGEST:
                _ingest_cases(all_events)

        elapsed = round(time.time() - start, 2)
        _plog(f"Pipeline completata in {elapsed}s — {len(all_events)} eventi")
        _progress_set(phase="done", current_domain=None, finished_at=now_iso(),
                      events=len(all_events), running=False)

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        _progress_set(phase="error", current_domain=None, finished_at=now_iso(), running=False)
    finally:
        _running = False


def _fetch_service(name: str, url: str) -> tuple:
    """Single service fetch, returns (name, result_or_None)."""
    try:
        r = _session.get(url, timeout=TIMEOUT)
        if not r.ok:
            # CODE-71: resta «nessun dato», ma con una riga: prima solo le eccezioni lasciavano traccia.
            logger.warning(f"  {name} error: HTTP {r.status_code} ({sanitize_log_input(url)})")
            return (name, None)
        return (name, r.json())
    except Exception as e:
        logger.warning(f"  {name} error: {sanitize_log_input(str(e))}")
        return (name, None)


def _gather_intelligence(domain: str, req: TriggerRequest) -> dict:
    """
    Chiama i servizi di intelligence in PARALLELO.
    DNS + Cert + HTTP + WHOIS + Reputation girano concorrentemente:
    il tempo totale è max(componenti) invece di sum(componenti).
    """
    from concurrent.futures import ThreadPoolExecutor

    intel = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}

    # Costruisci la lista dei task da eseguire.
    # SEC-14: il dominio entra codificato, così un `&`, `#` o `?` nel nome non cambia i parametri della chiamata.
    q = quote(domain, safe="")
    tasks = [
        ("dns", f"{DNS_URL}/dns?domain={q}&full=true&subdomains=true"),
        ("cert", f"{CERT_URL}/cert?domain={q}"),
        ("http", f"{HTTP_URL}/http?domain={q}"),
    ]
    if req.include_whois:
        tasks.append(("whois", f"{WHOIS_URL}/whois?domain={q}"))
    if req.include_reputation:
        tasks.append(("reputation", f"{REP_URL}/reputation?domain={q}"))

    # Esegui in parallelo (guard contro tasks vuoto)
    with ThreadPoolExecutor(max_workers=max(len(tasks), 1)) as executor:
        futures = [executor.submit(_fetch_service, name, url) for name, url in tasks]
        for future in futures:
            name, result = future.result()
            intel[name] = result

    return intel


@router.get("/intel", tags=["Intelligence"])
def get_domain_intel(client: str, domain: str):
    """
    Full intelligence for a domain: current snapshot + baseline diff history.
    Populates the dashboard Intelligence tab. Requires INTEL_STORE enabled.
    """
    if not INTEL_STORE:
        return JSONResponse(status_code=404,
                            content={"error": "intel store disabled (set INTEL_STORE=true)"})
    return intel_store.get_intel(client, domain)


app.include_router(router)
