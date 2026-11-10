"""
Classifier Service (:8007)
Baseline diffing + auto-classificazione varianti.
"""

import os, json, logging, unicodedata
from pathlib import Path
from fastapi import FastAPI, APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from shared.security import apply_security, sanitize_log_input
from shared.utils import now_iso, _CONTROL_CHARS, collection_failed, dns_unknown_rtypes, reputation_source_unobserved
from shared.constants import (SEVERITY_MAP, severity_rank, KNOWN_PARKING_NS, KNOWN_PARKING_IPS, AGE_THIRD_PARTY_DAYS,
                               MARKETPLACE_NS, PRIVACY_MX_PROVIDERS, FORWARDING_MX_PROVIDERS,
                               ENTERPRISE_CERT_PROVIDERS, PARKING_MX)

app = FastAPI(title="Classifier", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("classifier")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLASS] %(message)s")

BASELINE_DIR = Path(os.environ.get("BASELINE_DIR", "/data/baselines"))


@app.get("/health")
def health():
    return {"status": "healthy", "service": "classifier", "version": "4.0.0"}


# ═══════════════════════════════════════════════════════════════
# AUTO-CLASSIFICAZIONE VARIANTI
# ═══════════════════════════════════════════════════════════════

class VariantInput(BaseModel):
    # SCO-05 caso #9 (security-reviewer): senza un tetto, un dominio
    # anomalmente lungo è un amplificatore di DoS non autenticato su questo
    # endpoint (`_has_mixed_script` sotto itera carattere per carattere).
    # 253 = lunghezza massima di un FQDN, coerente con dnstwist_engine.py:38.
    domain: str = Field(..., max_length=253)
    fuzzer: str = ""
    dns: Optional[dict] = None
    cert: Optional[dict] = None
    http: Optional[dict] = None
    whois: Optional[dict] = None
    reputation: Optional[dict] = None
    # CODE-15 + CODE-14 (riunificati, architettura B2): {nome_sezione: bool},
    # True se quella sezione è fallita in questo ciclo. Costruito UNA VOLTA
    # dall'orchestrator (dove i dict sono ancora nella forma dei collector) e
    # propagato qui — vedi orchestrator.py:_build_collection_status. Opzionale:
    # una chiamata che non lo passa (test preesistenti, chiamate dirette) non
    # deve rompersi.
    collection_status: Optional[dict] = None


@router.post("/classify/variant", tags=["Classification"])
def classify_variant_endpoint(v: VariantInput):
    return classify_variant(v)


def _domain_age(whois_data: dict) -> dict:
    """Analizza l'età del dominio dai dati WHOIS.

    Ritorna: {age_days, created, updated, recently_reregistered}.
    La data di registrazione è il discriminante più forte per il typosquatting:
    un dominio registrato PRIMA dell'inizio di una campagna ostile è quasi sempre
    una terza parte legittima, mentre uno registrato di recente è un candidato reale.

    ATTENZIONE ai falsi negativi: un dominio scaduto e RI-REGISTRATO da un attaccante
    ha una creation_date vecchia ma è pericoloso. Rileviamo questo caso confrontando
    updated_date con creation_date: se il dominio è "vecchio" ma aggiornato di recente
    (possibile cambio di titolare), NON lo trattiamo come terza parte sicura.
    """
    from datetime import datetime
    out = {"age_days": None, "created": None, "updated": None, "recently_reregistered": False}

    def _coerce(val):
        # python-whois often returns creation_date/updated_date as a LIST of dates
        # (multiple registry records). Take the earliest for creation. Also accept
        # datetime objects directly.
        # SECURITY: the registrant controls their own WHOIS, so cap work to prevent
        # a hostile record (huge list / huge string) from causing CPU DoS.
        if val is None:
            return None
        if isinstance(val, list):
            parsed = [p for p in (_parse(x) for x in val[:10]) if p]
            return min(parsed) if parsed else None
        if isinstance(val, datetime):
            return val.replace(tzinfo=None)
        return _parse(val)

    def _parse(s):
        if isinstance(s, datetime):
            return s.replace(tzinfo=None)
        # Only strings carry a parseable date; ignore dict/bytes/int/nested lists.
        if not isinstance(s, str):
            return None
        # Bound length: a real date string is short; anything longer is junk/hostile.
        s = s.strip()[:40]
        # normalize: drop trailing Z, fractional seconds, timezone offsets
        s = s.replace("Z", "").split(".")[0].split("+")[0].strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                    "%d-%b-%Y", "%Y/%m/%d", "%d/%m/%Y", "%d.%m.%Y"):
            try:
                return datetime.strptime(s[:19] if "T" in s or ":" in s else s[:10], fmt)
            except ValueError:
                continue
        return None

    created = _coerce(whois_data.get("creation_date"))
    updated = _coerce(whois_data.get("updated_date"))
    if not created:
        return out
    now = datetime.utcnow()
    age_days = (now - created).days
    # A creation date in the future is corrupt/hostile WHOIS data: clamp to 0 and
    # treat as "unknown age" rather than a large negative number.
    if age_days < 0:
        return out
    out["age_days"] = age_days
    out["created"] = created.strftime("%Y-%m-%d")
    if updated:
        out["updated"] = updated.strftime("%Y-%m-%d")
        days_since_update = (now - updated).days
        if age_days > 730 and 0 <= days_since_update < 120:
            out["recently_reregistered"] = True
    return out


def _decode_and_normalize_domain(domain: str) -> str:
    """SCO-05: decodifica i soli label punycode (`xn--...`) e applica NFKC,
    così `_has_mixed_script` sotto opera sui caratteri Unicode reali del
    dominio invece che sull'ASCII-Compatible-Encoding — un omografo reale
    come `xn--80ak6aa92e.com` è ASCII puro finché non viene decodificato.
    Stdlib soltanto (codec `idna` incorporato, `unicodedata`): nessuna
    dipendenza nuova. Fallback conservativo: un label punycode malformato
    resta invariato invece di far fallire l'intera classificazione — un
    dominio proveniente da dnstwist non è dato fidato.
    """
    labels = []
    for label in domain.split("."):
        if label.lower().startswith("xn--"):
            try:
                # I nomi DNS sono case-insensitive e i registri restituiscono
                # anche `XN--...`, ma il codec `idna` confronta il prefisso ACE
                # senza normalizzare il case: senza `lower()` un label maiuscolo
                # non verrebbe decodificato affatto, e l'analista leggerebbe
                # l'ACE grezzo invece del nome Unicode.
                labels.append(label.lower().encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return unicodedata.normalize("NFKC", ".".join(labels))


# SCO-05 (R7). `unicodedata` della stdlib non espone la proprietà Script di
# Unicode e nessuna dipendenza nuova è ammessa (CLAUDE.md §1.7): questa è una
# tabella minima di intervalli per i soli script che il campione reale e i
# confusable noti usano davvero. APPROSSIMAZIONE DICHIARATA, non UTS #39
# completo — un carattere fuori da questi intervalli non viene attribuito ad
# alcuno script e viene ignorato, quindi una mescolanza che coinvolga uno
# script non elencato NON viene segnalata (falso negativo, mai falso positivo:
# la regola accusa solo su ciò che riconosce).
# Han, Hiragana e Katakana condividono deliberatamente la stessa etichetta:
# UTS #39 li tratta come un profilo unico (giapponese), quindi `日本の例` è un
# nome ordinario e non una mescolanza.
_SCRIPT_RANGES = (
    ("Latin", ((0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F),
               (0x1E00, 0x1EFF), (0x2C60, 0x2C7F), (0xA720, 0xA7FF))),
    ("Greek", ((0x0370, 0x03FF), (0x1F00, 0x1FFF))),
    ("Cyrillic", ((0x0400, 0x052F), (0x2DE0, 0x2DFF), (0xA640, 0xA69F))),
    ("Hebrew", ((0x0590, 0x05FF),)),
    ("Arabic", ((0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
                (0xFB50, 0xFDFF), (0xFE70, 0xFEFF))),
    ("Han/Kana", ((0x2E80, 0x2FDF), (0x3005, 0x3005), (0x3007, 0x3007),
                  (0x3041, 0x30FF), (0x31F0, 0x31FF), (0x3400, 0x4DBF),
                  (0x4E00, 0x9FFF), (0xF900, 0xFAFF))),
)


def _script_of(ch: str):
    """Script del carattere secondo `_SCRIPT_RANGES`, o None se non elencato."""
    cp = ord(ch)
    for name, ranges in _SCRIPT_RANGES:
        for lo, hi in ranges:
            if lo <= cp <= hi:
                return name
    return None


# SCO-05 (R2, round 3). Sotto UTS #39 *Moderately Restrictive*, Latin +
# Han/Hiragana/Katakana nello STESSO label è un identificatore lecito — es.
# `bicカメラ` (BIC CAMERA, catena reale di elettronica giapponese), non una
# mescolanza sospetta. Eccezione ristretta a questa sola coppia: Latin +
# Cyrillic/Greek/altro (il vero omografo) resta rilevato, e qualunque terzo
# script nello stesso label fa uscire dall'eccezione.
_JAPANESE_COMBINABLE_SCRIPTS = frozenset({"Latin", "Han/Kana"})

# SCO-05 (R2, round 4). L'eccezione sopra esenta QUALUNQUE coppia
# {Latin, Han/Kana} guardando solo quali script compaiono nel label, mai
# quali caratteri — un confusable Han/Kana visivamente identico a una
# lettera/simbolo latino evade quindi nascosto in un nome altrimenti latino
# (PoC del verifier, `SCO-05` round 3, G6: `g口口gle-mail.com`). Lista curata
# a mano (nessun dataset esterno tipo UTS #39 confusables.txt, CLAUDE.md
# §1.7), NON esaustiva per costruzione — copre il PoC più le varianti della
# stessa batteria:
#   口  U+53E3  ideogramma "bocca": contorno quadrato, confusable con 'o'/'0'
#   ロ  U+30ED  katakana "ro": contorno quadrato, confusable con 'o'/'0'
#   ー  U+30FC  segno di prolungamento katakana: tratto orizzontale, confusable con '-'
#   一  U+4E00  ideogramma "uno": tratto orizzontale, confusable con '-'/'l'
# Deliberatamente ESCLUSI, perché compaiono nei nomi commerciali giapponesi
# legittimi della batteria di non-regressione e non sono confusable visivi di
# lettere latine: カ/メ/ラ (kamera, "camera"), 本/店 (honten, "sede
# principale"), シ/ョ/ッ/プ (shoppu, "shop") — includerli romperebbe
# l'eccezione che questi test proteggono.
_HAN_KANA_LATIN_CONFUSABLES = frozenset({"口", "ロ", "ー", "一"})


def _has_mixed_script(domain: str) -> bool:
    """SCO-05 (R7). True se un LABEL del dominio (già decodificato e
    normalizzato) mescola lettere di script diversi — es. una 'а' cirillica
    U+0430 fra lettere latine.

    L'analisi è per label, non sull'intero nome, perché in UTS #39
    l'identificatore è il label: `аррӏе.com` è un whole-script confusable
    (label cirillico puro + TLD ASCII), non un mixed-script, e valutare il
    nome intero renderebbe la regola vera per qualunque IDN monoscript sotto
    un TLD ASCII."""
    for label in domain.split("."):
        scripts = set()
        for ch in label:
            if not ch.isalpha():
                continue
            script = _script_of(ch)
            if script is None:
                continue
            scripts.add(script)
        if len(scripts) > 1 and (
            scripts != _JAPANESE_COMBINABLE_SCRIPTS
            or any(ch in _HAN_KANA_LATIN_CONFUSABLES for ch in label)
        ):
            return True
    return False


# SCO-05 (BASSO-7). Il nome decodificato viene interpolato nelle rationale del
# blocco omografo, e NFKC ESPANDE: `U+FDFA` diventa 18 caratteri, quindi un
# dominio di 244 caratteri ne produce oltre 4400 — sopra il `max_length=2000`
# di `CaseIngest.rationale`, che farebbe rifiutare l'ingest e perdere il caso
# in silenzio. Stesso tetto della lunghezza massima di un FQDN, coerente con
# `VariantInput.domain`; stessa regola di casa di `_GUARD_RATIONALE_CAP`.
_HOMOGLYPH_DECODED_CAP = 253


def _display_decoded(decoded: str) -> str:
    """Forma del nome decodificato sicura da interpolare in una rationale:
    caratteri di controllo rimossi (`_CONTROL_CHARS`, regola CLS-01s — la
    rationale finisce in un evento NDJSON e nella dashboard) e lunghezza
    limitata (v. `_HOMOGLYPH_DECODED_CAP`)."""
    return _CONTROL_CHARS.sub("", decoded)[:_HOMOGLYPH_DECODED_CAP]


def classify_variant(v: VariantInput):
    """Auto-classificazione di una variante dnstwist."""
    logger.info(f"Classify variant: {sanitize_log_input(v.domain)} ({sanitize_log_input(v.fuzzer)})")
    return _apply_collection_guard(v, _classify_by_rules(v))


# CODE-23: uniche le classificazioni con severità di CASO superiore a
# `insufficient_data` (MEDIUM in CLASSIFICATION_SEVERITY, orchestrator.py:46-59)
# sopravvivono alla guardia di raccolta fallita (`_apply_collection_guard` sotto)
# — oggi solo `suspicious` (HIGH). Non importata dall'orchestrator: classifier.py
# non deve dipendere all'indietro da chi già lo importa (duplicazione tracciata
# a parte in CODE-27).
_SURVIVES_COLLECTION_GUARD = {"suspicious"}

# CODE-30: tetto sulla rationale della guardia. La regola che ha risposto
# prima della guardia può interpolare dati controllati dal dominio osservato
# (ns_str, a_records, mx_str, cert_cns, hidden_summary), quindi la sua
# rationale originale va troncata se necessario — mai scartata, come faceva
# il difetto. Stesso ordine di grandezza del tetto già in uso in casa per
# campi testuali attacker-controlled (`_cap_ioc`, shared/utils.py:514-523).
_GUARD_RATIONALE_CAP = 500

# COL-02: i soli tipi che le regole di `_classify_by_rules` leggono come
# presenza/assenza (A: sito, MX: posta, NS: parking/marketplace). TXT/SOA/AAAA/
# CNAME `unknown` non cambiano nessun esito e non devono attivare la guardia.
_DNS_RULE_RTYPES = frozenset({"A", "MX", "NS"})


def _undetermined_dns(v: VariantInput) -> frozenset:
    """COL-02: fra A, MX e NS, i tipi di cui il DNS non ha dato risposta in questo
    ciclo (SERVFAIL, REFUSED, trasporto, pacchetto non parsabile): `[]` lì NON
    significa «assente». Si legge dal payload (`records_status`), non da ciò che
    dichiara il chiamante; `collection_status["dns"]` (modulo `None` o fallito, senza
    stato per tipo) li rende indeterminati tutti e tre. Stato mancante = noto, come per
    i payload di prima di RES-01."""
    if (v.collection_status or {}).get("dns"):
        return _DNS_RULE_RTYPES
    return frozenset(dns_unknown_rtypes(v.dns) & _DNS_RULE_RTYPES)


def _classify_by_rules(v: VariantInput):
    """Le regole di classificazione (ordine di priorità), invariate rispetto a
    prima di CODE-23. La guardia di raccolta fallita non vive più qui dentro:
    vive in `_apply_collection_guard`, applicata all'esito qualunque sia la
    regola che lo ha prodotto — non solo quando nessuna regola scatta."""
    dns = v.dns or {}
    http = v.http or {}
    cert = v.cert or {}
    whois_data = v.whois or {}

    records = dns.get("records") or {}
    a_records = records.get("A") or []
    mx_records = records.get("MX") or []
    ns_records = records.get("NS") or []
    undetermined = _undetermined_dns(v)

    # Estrai info HTTP
    http_checks = [c for c in (http.get("checks") or []) if isinstance(c, dict)]
    any_http_active = any(c.get("status_code") and c["status_code"] < 400 for c in http_checks)
    max_content_len = max((c.get("content_length") or 0 for c in http_checks), default=0)

    # Estrai info cert
    _ct = cert.get("ct_certificates") or {}
    # CODE-18: crt.sh può dare `"common_name": null` e il payload arriva così com'è: un elemento che non è una
    # stringa faceva fallire con 500 il confronto coi provider enterprise. Solo i nomi contano.
    _raw_cns = _ct.get("unique_cn")
    cert_cns = [cn for cn in _raw_cns if isinstance(cn, str)] if isinstance(_raw_cns, list) else []

    mx_str = " ".join(mx_records).lower()
    ns_str = " ".join(ns_records).lower()
    hidden_summary = []

    # ── Età del dominio: calcolata PRIMA delle regole, perché modula la severità ──
    # Un segnale debole (tag nascosti, MX senza sito) su un dominio registrato molti anni
    # prima della campagna ostile non è un allarme: è il profilo normale di una terza parte
    # legittima. Su un dominio recente lo stesso segnale è invece rilevante.
    # NB: `recently_reregistered` NON entra qui. Il campo WHOIS updated_date cambia anche
    # al semplice rinnovo annuale, quindi quasi ogni dominio storico ancora attivo
    # risulterebbe "ri-registrato": usarlo per alzare la severità produce falsi positivi in
    # massa. Serve invece più sotto, dove impedisce lo scagionamento automatico a LOW.
    age = _domain_age(whois_data)
    is_aged = age["age_days"] is not None and age["age_days"] > AGE_THIRD_PARTY_DAYS
    age_years = (age["age_days"] // 365) if age["age_days"] else 0

    def _aged_note(signal: str) -> str:
        return (f"{signal} su dominio registrato il {age['created']} (~{age_years} anni fa), "
                f"prima della finestra di registrazione ostile: severità ridotta, "
                f"verifica manuale consigliata")

    # ── Regole di classificazione (ordine di priorità) ──

    # PARKING
    if any_http_active and max_content_len <= 200:
        return _result(v.domain, "parking", "high",
                       "http_active_minimal_content",
                       "HTTP attivo con contenuto minimo (<200b), tipico di pagine redirect/parking")

    if any(pk in ns_str for pk in KNOWN_PARKING_NS):
        return _result(v.domain, "parking", "high",
                       "known_parking_ns",
                       f"NS su provider parking noto: {ns_str}")

    if any(ip in KNOWN_PARKING_IPS for ip in a_records):
        return _result(v.domain, "parking", "high",
                       "known_parking_ip",
                       f"IP parking noto: {a_records}")

    # IN VENDITA
    if any(mk in ns_str for mk in MARKETPLACE_NS):
        return _result(v.domain, "for_sale", "high",
                       "marketplace_ns",
                       f"NS su marketplace domini: {ns_str}")

    if any(pmx in mx_str for pmx in PARKING_MX):
        return _result(v.domain, "for_sale", "medium",
                       "parking_mx",
                       f"MX su parking provider: {mx_str}")

    # SOSPETTO (hidden elements) — priorità su legittimo probabile
    # Un sito con hidden forms è sospetto ANCHE SE ha contenuto sostanziale
    hidden_risk = 0
    for check in http_checks:
        he = check.get("hidden_elements", {})
        if isinstance(he, dict):
            hr = he.get("risk_indicators", 0)
            if hr > hidden_risk:
                hidden_risk = hr
                hidden_summary = he.get("summary", [])
    if hidden_risk >= 30:
        # Weak signal: tracking pixels, HTML comments and iframes are common on ordinary
        # marketing sites. On a long-established domain this is not an alarm.
        if is_aged:
            return _result(v.domain, "needs_review", "medium",
                           "hidden_elements_aged_domain",
                           _aged_note(f"Tag nascosti ({hidden_risk}/100: {'; '.join(hidden_summary[:2])})"))
        return _result(v.domain, "suspicious", "high",
                       "hidden_elements_detected",
                       f"Tag nascosti ad alto rischio ({hidden_risk}/100): {'; '.join(hidden_summary[:3])}")

    # OMOGRAFO (SCO-05): la forma prevale sul contenuto quando il dominio NON
    # è `is_aged` (Domanda 1, decisione utente 2026-08-08, opzione A) — un
    # omografo con "sito attivo e legittimo" non deve scagionarsi da solo
    # sotto la regola successiva. Dopo i segnali più specifici già scattati
    # sopra (parking/for-sale/hidden risk>=30, posizionamento più
    # conservativo tra le due proposte valutate), prima del ramo "legittimo
    # probabile". Categoria uniforme `suspicious`/HIGH in ogni ramo — MAI
    # CRITICAL da nome-solo (Domanda 2, opzione A): l'invariante dei due
    # canali di severità (shared/constants.py:9-19) resta intatto anche per
    # lo script-mixing, il segnale più forte.
    if v.fuzzer == "homoglyph" and not is_aged:
        decoded = _decode_and_normalize_domain(v.domain)
        shown = _display_decoded(decoded)
        # Lo script-mixing è testato PRIMA di qualunque condizione sul WHOIS, e
        # l'ordine è il punto: è un'osservazione POSITIVA del nome, sempre
        # integralmente disponibile, quindi non appartiene alla classe di
        # difetto «assente ≠ fallito» (CODE-01) e non deve poter essere
        # soppresso dall'ignoranza sull'età.
        if _has_mixed_script(decoded):
            return _result(v.domain, "suspicious", "high",
                           "homoglyph_script_mixing",
                           f"Omografo con mescolanza di script Unicode entro uno stesso label, "
                           f"dopo decodifica punycode ({shown}): forte indicatore di potenziale "
                           f"impersonificazione")
        # `not is_aged` è vero in tre situazioni diverse: dominio giovane,
        # WHOIS fallito, WHOIS mai raccolto. Solo la prima è un segnale
        # osservato; le altre due sono assenza di informazione, e su intel
        # reale elevavano a HIGH domini di cui non si sa nulla (revisione 2 del
        # criterio, decisione utente 2026-08-11). `age_days` valorizzato è
        # l'unica prova che una data di registrazione sia stata davvero letta;
        # `collection_status` esclude in più il caso di un WHOIS tentato e
        # fallito che abbia comunque prodotto una data parziale. R3 (round 3):
        # `collection_status` dipende dalla disciplina del CHIAMANTE — se non
        # lo marca, un WHOIS fallito ma con `error` popolato nel dict stesso
        # (il fallback CLI di whois_intel.py: data parziale + errore insieme)
        # eludeva la guardia. `collection_failed` (shared/utils.py, già punto
        # unico di verità per l'orchestrator) ispeziona direttamente il dict
        # WHOIS, indipendente da cosa dichiara il chiamante.
        whois_observed = (age["age_days"] is not None
                          and not (v.collection_status or {}).get("whois")
                          and not collection_failed(whois_data))
        if whois_observed:
            if a_records or mx_records:
                return _result(v.domain, "suspicious", "high",
                               "homoglyph_resolving",
                               f"Dominio omografo (fuzzer=homoglyph, {shown}) con "
                               f"infrastruttura attiva (A e/o MX): la sola registrazione è già "
                               f"evidenza di intento")
            # COL-02: con A o MX non risposti `[]` non prova la dormienza. L'HIGH viene
            # dal nome e dall'età (osservati), non dal DNS: un SERVFAIL provocato da chi
            # controlla la zona del lookalike non deve poterlo far scendere. La rationale
            # non afferma l'assenza di infrastruttura.
            if "A" in undetermined or "MX" in undetermined:
                return _result(v.domain, "suspicious", "high",
                               "homoglyph_not_aged_dns_unknown",
                               f"Dominio omografo (fuzzer=homoglyph, {shown}) non aged, con A o MX "
                               f"non determinati (il DNS non ha risposto) e nessun record visto: "
                               f"la severità viene da nome ed età, non dall'infrastruttura, "
                               f"verifica manuale")
            return _result(v.domain, "suspicious", "high",
                           "homoglyph_dormant_not_aged",
                           f"Dominio omografo (fuzzer=homoglyph, {shown}) non aged e senza "
                           f"infrastruttura attiva: dormiente non è sufficiente a scagionare, "
                           f"verifica manuale")
        # Età ignota e nessuna mescolanza di script: nessuna elevazione. La
        # cascata prosegue, e se una raccolta è fallita la guardia a valle
        # produce `insufficient_data` invece di un HIGH su zero informazione.

    # LEGITTIMO PROBABILE
    if any(ep in cn for ep in ENTERPRISE_CERT_PROVIDERS for cn in cert_cns):
        return _result(v.domain, "legitimate_probable", "medium",
                       "enterprise_cert_provider",
                       f"Certificati di provider enterprise: {cert_cns}")

    # Un sito con contenuto sostanziale è di norma legittimo, MA se il dominio è
    # recente E ha MX attivo, il "sito di facciata + email" è un profilo di typosquat,
    # non di terza parte legittima: non declassare, lascialo alla verifica.
    _recent = age["age_days"] is not None and age["age_days"] < AGE_THIRD_PARTY_DAYS
    if any_http_active and max_content_len > 3000 and not (_recent and mx_records):
        return _result(v.domain, "legitimate_probable", "low",
                       "http_active_substantial_content",
                       f"Sito attivo con contenuto sostanziale ({max_content_len}b)")

    # SOSPETTO (infrastruttura)
    # COL-02: «MX senza A» richiede un A determinato; con A non risposto non si sa
    # se il sito c'è (la guardia a valle declassa a `insufficient_data`).
    if mx_records and not a_records and "A" not in undetermined:
        # An email-only domain is the normal profile of a small business that uses the
        # name just for mail. It is a threat signal only when the domain is recent.
        if is_aged:
            return _result(v.domain, "needs_review", "medium",
                           "mx_only_aged_domain",
                           _aged_note("Profilo solo-email (MX senza record A)"))
        return _result(v.domain, "suspicious", "high",
                       "mx_only_no_web",
                       "MX attivo senza record A, profilo solo-email")

    if any(pp in mx_str for pp in PRIVACY_MX_PROVIDERS):
        if is_aged:
            return _result(v.domain, "needs_review", "medium",
                           "privacy_mx_aged_domain",
                           _aged_note(f"MX su provider ad alta privacy ({mx_str[:60]})"))
        return _result(v.domain, "suspicious", "high",
                       "privacy_mx_provider",
                       f"MX su provider ad alta privacy: {mx_str}")

    if any(fw in mx_str for fw in FORWARDING_MX_PROVIDERS):
        if is_aged:
            return _result(v.domain, "needs_review", "medium",
                           "forwarding_mx_aged_domain",
                           _aged_note(f"MX su email forwarding ({mx_str[:60]})"))
        return _result(v.domain, "suspicious", "medium",
                       "forwarding_mx",
                       f"MX su email forwarding: {mx_str}")

    # Hidden elements rischio moderato
    if hidden_risk >= 15:
        return _result(v.domain, "needs_review", "medium",
                       "hidden_elements_moderate",
                       f"Tag nascosti rilevati ({hidden_risk}/100): {'; '.join(hidden_summary[:3])}")

    # ── ETÀ DEL DOMINIO: classificazione terzo-parte per domini inerti ──
    # La data di registrazione è il discriminante più forte: un dominio registrato
    # molto prima di una campagna ostile, e inerte da allora, è quasi sempre una
    # terza parte legittima. Questo toglie dalla coda i molti domini pre-campagna
    # (nomi propri, terzi storici) oggi marcati genericamente "needs_review".
    if age["age_days"] is not None:
        # Cautela anti-falso-negativo: se il dominio è vecchio MA aggiornato di recente
        # (possibile ri-registrazione dopo scadenza / cambio titolare), NON lo declassiamo.
        if age["recently_reregistered"]:
            return _result(v.domain, "needs_review", "medium",
                           "old_domain_recently_updated",
                           f"Dominio datato ({age['created']}) ma con record WHOIS aggiornato di "
                           f"recente ({age['updated']}): può trattarsi di un semplice rinnovo, "
                           f"oppure di un cambio di titolare. Non scagionato in automatico, "
                           f"verifica manuale")
        # Vecchio (>18 mesi) e senza segnali ostili emersi sopra → terza parte probabile
        if age["age_days"] > AGE_THIRD_PARTY_DAYS:
            yrs = age["age_days"] // 365
            return _result(v.domain, "likely_third_party", "low",
                           "predates_campaign",
                           f"Registrato il {age['created']} (~{yrs} anni fa), prima della finestra "
                           f"tipica di registrazione ostile e senza segnali di minaccia, "
                           f"probabile terza parte preesistente")

    # Dominio recente senza segnali: non è "nessuna regola", è un look-alike registrato
    # nella finestra di campagna e ancora inerte. Profilo tipico del dominio tenuto in
    # caldo per un uso successivo: va monitorato per l'attivazione, non archiviato.
    if age["age_days"] is not None and not is_aged:
        return _result(v.domain, "needs_review", "medium",
                       "recent_registration_inactive",
                       f"Registrato il {age['created']} ({age['age_days']} giorni fa), nella "
                       f"finestra di registrazione ostile, ma attualmente senza contenuti né "
                       f"email attiva: possibile dominio dormiente, monitorare l'attivazione")

    # DA VERIFICARE
    return _result(v.domain, "needs_review", "low",
                   "no_matching_rule",
                   "Nessuna regola corrisponde con sufficiente certezza")


def _result(domain, category, confidence, rule, rationale):
    action_map = {
        "parking": "monitor_passive",
        "for_sale": "monitor_passive",
        "legitimate_probable": "whitelist_candidate",
        "likely_third_party": "whitelist_candidate",
        "suspicious": "block_and_monitor",
        "needs_review": "manual_review"
    }
    return JSONResponse(content={
        "domain": domain, "timestamp": now_iso(),
        "auto_classification": category,
        "confidence": confidence,
        "rule": rule,
        "rationale": rationale,
        "action": action_map.get(category, "manual_review"),
        "manual_review_required": category in ("needs_review", "suspicious")
    })


def _apply_collection_guard(v: VariantInput, response: JSONResponse) -> JSONResponse:
    """CODE-23. Decisione utente 2026-08-05: «non ho potuto guardare» non deve
    mai zittire «ho visto qualcosa di brutto», ma deve impedire di dire «sembra
    a posto» quando metà dei dati manca. Quando almeno una sezione NON-http fra
    whois/cert/reputation è fallita (`http` è l'unica che un attaccante
    controlla a comando — vedi CODE-15+CODE-14 sopra), l'esito prodotto dalle
    regole viene SOVRASCRITTO con `insufficient_data`, a meno che quell'esito
    abbia già severità di caso superiore (solo `suspicious`,
    `_SURVIVES_COLLECTION_GUARD`). Applicata a valle dell'intera cascata di
    regole, non prima di essa: la guardia in cima scavalcherebbe anche le
    classificazioni accusatorie che devono sopravviverle.
    """
    failed_sections = [name for name, failed in (v.collection_status or {}).items() if failed]
    # COL-02: il DNS si deriva anche dal payload — un SERVFAIL su A, MX o NS è «non ho
    # potuto guardare» anche se il chiamante non lo dichiara in `collection_status`.
    if _undetermined_dns(v) and "dns" not in failed_sections:
        failed_sections.append("dns")
    if not any(name != "http" for name in failed_sections):
        return response
    data = json.loads(response.body)
    if data.get("auto_classification") in _SURVIVES_COLLECTION_GUARD:
        return response
    rationale = f"Raccolta dati fallita per: {', '.join(failed_sections)} — nessun segnale osservabile"
    # CODE-30 round 2: `failed_sections` viene dalle CHIAVI di `collection_status`,
    # un `Optional[dict]` non validato (`VariantInput.collection_status`,
    # classifier.py:51) — una chiave enorme gonfia già questo template, prima
    # che il budget qui sotto abbia una qualunque possibilità di intervenire.
    # Il tetto va applicato al template stesso, non solo alla coda appesa.
    rationale = rationale[:_GUARD_RATIONALE_CAP]
    underlying_rule = data.get("rule")
    # CODE-30: se una regola aveva risposto, conserva il suo "perché" invece
    # di scartarlo — ma non per `no_matching_rule`, dove non c'è nulla a cui
    # la sezione fallita avrebbe potuto corrispondere. Solo la rationale
    # originale (dati osservati) è troncata quando serve; il nome della
    # regola no.
    if underlying_rule != "no_matching_rule":
        prefix = f" — avrebbe corrisposto a: {underlying_rule} ("
        suffix = ")"
        budget = max(0, _GUARD_RATIONALE_CAP - len(rationale) - len(prefix) - len(suffix))
        # Budget azzerato (template già al tetto) non deve produrre un guscio
        # vuoto "... (" + "" + ")": se non resta spazio per la rationale
        # originale, ometti l'intera coda invece di appenderla vuota.
        if budget > 0:
            rationale += prefix + data.get("rationale", "")[:budget] + suffix
    return _result(v.domain, "insufficient_data", "low",
                   "module_collection_failed", rationale)


# ═══════════════════════════════════════════════════════════════
# BATCH CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

class BatchInput(BaseModel):
    # Cap batch size: a legitimate scan classifies at most a few hundred variants;
    # an unbounded list is a DoS vector.
    variants: list[VariantInput] = Field(..., max_length=1000)


@router.post("/classify/batch", tags=["Classification"])
def classify_batch(batch: BatchInput):
    """Classifica un batch di varianti."""
    results = []
    counts = {"parking": 0, "for_sale": 0, "legitimate_probable": 0, "likely_third_party": 0,
              "suspicious": 0, "needs_review": 0}

    for v in batch.variants:
        resp = classify_variant(v)
        data = json.loads(resp.body)
        results.append(data)
        cat = data.get("auto_classification", "needs_review")
        counts[cat] = counts.get(cat, 0) + 1

    return JSONResponse(content={
        "timestamp": now_iso(),
        "total": len(results),
        "summary": counts,
        "results": results
    })


# ═══════════════════════════════════════════════════════════════
# BASELINE DIFFING
# ═══════════════════════════════════════════════════════════════

class DiffInput(BaseModel):
    domain: str
    client: str
    legitimate: str = ""  # dominio legittimo del cliente
    current: dict  # output aggregato dei servizi di intelligence
    baseline: Optional[dict] = None  # baseline precedente


@router.post("/diff", tags=["Diffing"])
def baseline_diff(inp: DiffInput):
    """Confronta stato corrente con baseline, genera alert."""
    logger.info(f"Diff: {sanitize_log_input(inp.domain)} client={sanitize_log_input(inp.client)}")
    alerts = []
    prev = inp.baseline or {}
    curr = inp.current

    is_legit = (inp.domain == inp.legitimate)

    # Note: a key may be PRESENT with value None (e.g. "cert": null when a domain
    # has no certificates). dict.get(k, {}) returns None in that case, not {}.
    # Use (x or {}) everywhere so a None value also falls back to empty.

    def _has_baseline(section: str) -> bool:
        """True se per questa sezione esiste un'osservazione precedente con cui
        confrontarsi.

        Una sezione assente o `None` in baseline NON è una baseline a zero: è
        l'assenza di una baseline. L'orchestrator salva `None` quando il modulo
        fallisce e non c'era nulla di pregresso (CODE-01), quindi confrontarci
        contro produrrebbe un delta pari all'intera storia — «25 nuovi certificati»
        alla prima raccolta riuscita, che è esattamente il difetto che CODE-01
        elimina nell'altra direzione. Alla prima osservazione valida la baseline
        si popola in silenzio.
        """
        return isinstance(prev.get(section), dict)

    # DNS diff
    if _has_baseline("dns"):
        # COL-02: un tipo `unknown` nel CORRENTE non è un'osservazione, quindi non si confronta:
        # «assente» e «il DNS non ha risposto» non sono lo stesso fatto. `unknown` solo nella
        # baseline invece sì: con il riporto dell'orchestrator vuol dire «mai noto prima», e
        # confrontarlo come assente fa allertare il primo valore noto non vuoto come un cambio
        # ordinario e nessun alert il noto vuoto (SEC-31: senza, il risveglio di un dominio
        # dopo soli guasti restava muto).
        unknown = dns_unknown_rtypes(curr.get("dns"))
        _diff_records((prev.get("dns") or {}).get("records", {}),
                      (curr.get("dns") or {}).get("records", {}), alerts, unknown)
        _diff_email_auth((prev.get("dns") or {}).get("email_auth", {}),
                         (curr.get("dns") or {}).get("email_auth", {}), alerts)
        _diff_dns_stale(prev.get("dns"), curr.get("dns"), alerts)

    # HTTP diff
    if _has_baseline("http"):
        _diff_http((prev.get("http") or {}).get("checks", []),
                   (curr.get("http") or {}).get("checks", []), alerts, is_legit)
        _diff_hidden_elements(curr.get("http") or {}, prev.get("http") or {}, is_legit, alerts)

    # Cert diff
    if _has_baseline("cert"):
        _diff_certs((prev.get("cert") or {}).get("ct_certificates", {}),
                    (curr.get("cert") or {}).get("ct_certificates", {}), alerts)

    # WHOIS diff
    if _has_baseline("whois"):
        _diff_whois(prev.get("whois") or {}, curr.get("whois") or {}, alerts)

    # Reputation diff
    if _has_baseline("reputation"):
        _diff_reputation(prev.get("reputation") or {}, curr.get("reputation") or {}, alerts)

    # Status complessivo
    max_sev = max((SEVERITY_MAP.get(a["type"], "LOW") for a in alerts), default="CLEAN",
                  key=severity_rank)

    return JSONResponse(content={
        "domain": inp.domain, "client": inp.client, "timestamp": now_iso(),
        "alerts": alerts,
        "alert_count": len(alerts),
        "max_severity": max_sev,
        "overall_status": f"{max_sev} — {'AZIONE IMMEDIATA' if max_sev == 'CRITICAL' else 'ATTENZIONE' if max_sev == 'HIGH' else 'NESSUNA DIVERGENZA' if max_sev == 'CLEAN' else 'MONITORARE'}",
        "new_baseline": curr
    })


def _diff_records(prev: dict, curr: dict, alerts: list, unknown=frozenset()):
    type_map = {"A": "a_record_changed", "MX": "mx_record_changed",
                "NS": "ns_changed", "TXT": "txt_changed", "SOA": "soa_changed"}
    for rtype, alert_type in type_map.items():
        if rtype in unknown:
            continue
        p = sorted(prev.get(rtype, []))
        c = sorted(curr.get(rtype, []))
        if p != c and (p or c):
            alerts.append(_alert(alert_type, f"Record {rtype} modificato: {p} → {c}",
                                 {"old": p, "new": c}))


def _diff_email_auth(prev: dict, curr: dict, alerts: list):
    def unknown(section: str) -> bool:
        # COL-02: stesso criterio di `_diff_records` (solo il corrente), per lo `status` di
        # SPF/DMARC/BIMI/CAA.
        return (curr.get(section) or {}).get("status") == "unknown"

    for field, alert_type in [("dmarc", "dmarc_changed"), ("dkim", "dkim_added"),
                               ("bimi", "bimi_added"), ("caa", "caa_changed")]:
        if unknown(field):
            continue
        p = (prev.get(field) or {}).get("present", False)
        c = (curr.get(field) or {}).get("present", False)
        if c and not p:
            alerts.append(_alert(alert_type, f"{field.upper()} aggiunto", {}))

    p_spf = (prev.get("spf") or {}).get("records", [])
    c_spf = (curr.get("spf") or {}).get("records", [])
    if p_spf != c_spf and (p_spf or c_spf) and not unknown("spf"):
        alerts.append(_alert("spf_changed", f"SPF modificato: {p_spf} → {c_spf}",
                             {"old": p_spf, "new": c_spf}))


# COL-12: un dato DNS riportato dall'orchestrator (COL-02/CODE-01: il DNS non ha risposto e
# ha copiato il ciclo precedente) non è un'osservazione. Oltre 72 h senza riosservarlo lo
# segnala, una volta per serie. Due gruppi perché solo A/MX/NS hanno già un segnale in
# eventi e casi (`dns_*_status`, `insufficient_data`): per gli altri è l'unico.
_DNS_STALE_AFTER_S = 72 * 3600
_DNS_STALE_GROUPS = (("dns_stale_core", ("A", "MX", "NS")),
                     ("dns_stale_other", ("AAAA", "CNAME", "SOA", "TXT", "bimi", "caa", "dmarc", "spf")))


def _dns_carried_ages(dns, parts) -> dict:
    """COL-12: età in secondi, per ognuna delle `parts`, dal marcatore `dns.carried_over`
    (`carried_at - observed_at`; `observed_at` null = ignota = infinita). Il `current` di
    `/diff` arriva dalla zona non autenticata e la baseline da file su disco: si scorre
    l'elenco delle parti, mai le chiavi del marcatore, e una voce illeggibile (non dict,
    istante non ISO) manca invece di sollevare. Nel corrente non genera alert; in baseline
    vale «non riportata» (età 0), al peggio un alert in più una volta. Un istante senza fuso
    vale UTC: sottrarre naive e aware solleva TypeError."""
    from datetime import datetime, timezone

    def _instant(value):
        try:
            ts = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    marker = dns.get("carried_over") if isinstance(dns, dict) else None
    if not isinstance(marker, dict):
        return {}
    ages = {}
    for part in parts:
        entry = marker.get(part)
        carried = _instant(entry.get("carried_at")) if isinstance(entry, dict) else None
        if carried is None:
            continue
        if entry.get("observed_at") is None:
            ages[part] = float("inf")
            continue
        observed = _instant(entry["observed_at"])
        if observed is not None:
            ages[part] = (carried - observed).total_seconds()
    return ages


def _diff_dns_stale(prev_dns, curr_dns, alerts: list):
    """COL-12: alert quando l'età di una parte riportata ATTRAVERSA la soglia fra baseline e
    corrente (baseline sotto, corrente sopra): una volta per serie, calcolato sui soli
    istanti del marcatore, senza orologio qui. Al più un alert per gruppo, che elenca le
    parti che hanno attraversato. Messaggio e dettaglio hanno solo nomi dell'elenco."""
    for alert_type, parts in _DNS_STALE_GROUPS:
        before, now = _dns_carried_ages(prev_dns, parts), _dns_carried_ages(curr_dns, parts)
        crossed = sorted(p for p, age in now.items()
                         if age >= _DNS_STALE_AFTER_S and before.get(p, 0) < _DNS_STALE_AFTER_S)
        if crossed:
            alerts.append(_alert(alert_type,
                                 f"Dato DNS riportato, non riosservato da almeno {_DNS_STALE_AFTER_S // 3600} h: "
                                 f"{', '.join(crossed)}", {"parts": crossed}))


def _diff_http(prev: list, curr: list, alerts: list, is_legit: bool = False):
    prev_urls = {c["url"]: c for c in prev if isinstance(c, dict)}
    for check in curr:
        if not isinstance(check, dict):
            continue
        url = check.get("url", "")
        p = prev_urls.get(url, {})
        if check.get("status_code") and check["status_code"] < 400:
            if not p.get("status_code") or p["status_code"] >= 400:
                alerts.append(_alert("http_activated", f"SITO ATTIVATO: {url} (HTTP {check['status_code']})", {}))
        if check.get("suspicious_patterns"):
            # Un'area di login è NORMALE sul dominio legittimo del cliente (portali,
            # gestionali, webmail) e su moltissimi siti di terzi. La presenza di
            # "login/password/utente" NON è di per sé phishing. Allerta solo quando
            # il pattern è una NOVITÀ rispetto alla baseline (un form di credenziali
            # comparso dove prima non c'era) E NON è il dominio legittimo.
            if is_legit:
                continue
            prev_patterns = {sp.get("pattern") for sp in (p.get("suspicious_patterns") or [])}
            for sp in check["suspicious_patterns"]:
                # solo pattern di credenziali realmente nuovi (non già presenti in baseline)
                if sp.get("pattern") in prev_patterns:
                    continue
                # ignora il semplice <form action> generico: serve un segnale di credenziali
                if "password" not in sp.get("pattern", "") and "login" not in sp.get("pattern", "") \
                   and "sign" not in sp.get("pattern", ""):
                    continue
                alerts.append(_alert("credential_form_detected",
                                     f"Nuovo pattern di credenziali su {url}: {sp['pattern']}", sp))


def _diff_certs(prev: dict, curr: dict, alerts: list):
    prev_total = prev.get("total", 0)
    curr_total = curr.get("total", 0)
    if curr_total > prev_total:
        new_count = curr_total - prev_total
        alerts.append(_alert("new_certificate_batch" if new_count > 10 else "new_certificate",
                             f"Nuovi certificati TLS: {new_count}", {"count": new_count}))


def _diff_whois(prev: dict, curr: dict, alerts: list):
    if prev.get("registrar") and curr.get("registrar") and prev["registrar"] != curr["registrar"]:
        alerts.append(_alert("whois_registrar_changed",
                             f"Registrar: {prev['registrar']} → {curr['registrar']}", {}))
    if prev.get("expiration_date") and curr.get("expiration_date"):
        if prev["expiration_date"] != curr["expiration_date"]:
            alerts.append(_alert("whois_renewed", f"Scadenza: {prev['expiration_date']} → {curr['expiration_date']}", {}))
    if prev.get("privacy_protected") and not curr.get("privacy_protected"):
        alerts.append(_alert("whois_privacy_removed", "WHOIS privacy rimossa", {}))


def _diff_reputation(prev: dict, curr: dict, alerts: list):
    # COL-16: una fonte non osservata (in errore) ha i numeri a zero ma non è una lettura, né in
    # baseline né nel ciclo corrente: confrontarla fa uscire un alert per un valore osservato
    # prima del guasto, o ne nasconde uno vero. Senza confronto, la prima osservazione riuscita
    # popola la baseline in silenzio (stesso principio di `_has_baseline`).
    pv = prev.get("virustotal") or {}
    cv = curr.get("virustotal") or {}
    if (cv.get("malicious", 0) > 0 and pv.get("malicious", 0) == 0
            and not reputation_source_unobserved(pv) and not reputation_source_unobserved(cv)):
        alerts.append(_alert("vt_malicious_detected",
                             f"VT malicious: {cv['malicious']}", cv))
    po = prev.get("otx") or {}
    co = curr.get("otx") or {}
    if (co.get("pulse_count", 0) > po.get("pulse_count", 0)
            and not reputation_source_unobserved(po) and not reputation_source_unobserved(co)):
        alerts.append(_alert("otx_pulse_detected",
                             f"OTX pulse: {co['pulse_count']}", co))


def _alert(alert_type: str, message: str, detail: dict) -> dict:
    return {
        "type": alert_type,
        "severity": SEVERITY_MAP.get(alert_type, "MEDIUM"),
        "message": message,
        "detail": detail,
        "timestamp": now_iso()
    }


def _diff_hidden_elements(curr_http: dict, prev_http: dict, is_legit: bool, alerts: list):
    """
    Confronta hidden elements tra cicli. Se il dominio è il legittimo del cliente,
    qualsiasi hidden element è CRITICAL (indica compromissione).
    """
    for check in curr_http.get("checks", []):
        he = check.get("hidden_elements", {})
        if not isinstance(he, dict):
            continue

        url = check.get("url", "?")
        risk = he.get("risk_indicators", 0)

        # Cerca se nella baseline precedente c'erano già hidden elements per questo URL
        prev_risk = 0
        for prev_check in prev_http.get("checks", []):
            if prev_check.get("url") == url:
                prev_he = prev_check.get("hidden_elements", {})
                if isinstance(prev_he, dict):
                    prev_risk = prev_he.get("risk_indicators", 0)
                break

        # Alert solo se NUOVI hidden elements (risk aumentato)
        if risk <= prev_risk:
            continue

        if is_legit:
            # ── DOMINIO LEGITTIMO: qualsiasi hidden element è CRITICAL ──
            # Indica possibile compromissione dell'infrastruttura del cliente
            if he.get("hidden_forms"):
                alerts.append(_alert("legit_hidden_form_detected",
                    f"⚠ COMPROMISSIONE: form nascosto rilevato su {url} (dominio LEGITTIMO del cliente). "
                    f"Possibile web skimmer o credential harvesting iniettato.",
                    {"url": url, "forms": he["hidden_forms"], "risk": risk}))

            if he.get("invisible_iframes"):
                alerts.append(_alert("legit_invisible_iframe_detected",
                    f"⚠ COMPROMISSIONE: iframe invisibile su {url} (dominio LEGITTIMO). "
                    f"Possibile caricamento contenuto malevolo.",
                    {"url": url, "iframes": he["invisible_iframes"], "risk": risk}))

            if he.get("suspicious_dead_markup"):
                alerts.append(_alert("legit_suspicious_dead_markup_detected",
                    f"⚠ COMPROMISSIONE: markup morto sospetto verso host esterno su {url} "
                    f"(dominio LEGITTIMO). Elemento mai renderizzato per costruzione "
                    f"(fallback content opaco).",
                    {"url": url, "markup": he["suspicious_dead_markup"], "risk": risk}))

            if he.get("obfuscated_js"):
                alerts.append(_alert("legit_obfuscated_js_detected",
                    f"⚠ COMPROMISSIONE: JavaScript offuscato su {url} (dominio LEGITTIMO). "
                    f"Indicatori: {', '.join(he['obfuscated_js'][0].get('indicators', []))}",
                    {"url": url, "scripts": he["obfuscated_js"], "risk": risk}))

            if he.get("meta_redirects"):
                target_url = he["meta_redirects"][0].get("target_url", "?")
                alerts.append(_alert("legit_meta_redirect_detected",
                    f"⚠ COMPROMISSIONE: meta redirect nascosto su {url} (dominio LEGITTIMO) "
                    f"verso {target_url}. Possibile hijack.",
                    {"url": url, "redirects": he["meta_redirects"], "risk": risk}))

            if he.get("hidden_divs_with_content"):
                for div in he["hidden_divs_with_content"]:
                    if div.get("contains_form") or div.get("contains_input"):
                        alerts.append(_alert("legit_content_injected",
                            f"⚠ COMPROMISSIONE: contenuto nascosto con form iniettato su {url} "
                            f"(dominio LEGITTIMO). Testo: {div.get('visible_text_preview', '')[:100]}",
                            {"url": url, "div": div, "risk": risk}))
                        break

            # Generico per qualsiasi hidden element su legit
            if risk >= 10 and not any(a["type"].startswith("legit_") for a in alerts[-5:]):
                alerts.append(_alert("legit_hidden_elements_detected",
                    f"⚠ Tag nascosti rilevati su {url} (dominio LEGITTIMO del cliente, risk {risk}/100). "
                    f"{'; '.join(he.get('summary', [])[:3])}",
                    {"url": url, "risk": risk, "summary": he.get("summary", [])}))

        else:
            # ── VARIANTE / TARGET: severity standard ──
            if risk >= 20:
                for item in he.get("summary", []):
                    alerts.append(_alert("hidden_elements_high_risk",
                        f"Tag nascosti su {url}: {item}",
                        {"risk": risk, "url": url}))

app.include_router(router)
