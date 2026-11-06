"""
Reputation Service (:8005)
Modulo 9 estratto — VirusTotal, AlienVault OTX, SecurityTrails + risk scoring.
"""

import os, logging, time, threading, math
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.constants import VT_NOT_FOUND_ERROR
from shared.utils import now_iso, _calc_score, _score_to_level

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = FastAPI(title="Reputation", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("reputation")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [REP] %(message)s")

VT_API_KEY = os.environ.get("VT_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
ST_API_KEY = os.environ.get("ST_API_KEY", "")

# PERF-01: token bucket condiviso per VT (free tier: 4 richieste/60s), sullo
# stesso principio del rate limiter WHOIS (whois_intel.py:65-71) — regola il
# ritmo PRIMA della chiamata, non con uno sleep incondizionato dopo la
# risposta. A differenza del gate WHOIS (intervallo fisso fra due chiamate),
# qui la finestra ammette un burst fino a VT_RATE_LIMIT chiamate: ogni
# chiamata reale (successo, 404 o errore) consuma comunque un posto nella
# finestra, quindi la quota resta rispettata indipendentemente dall'esito.
def _parse_rate_env(name: str, cast, default):
    # PERF-01 round 4 (decisione utente 2026-07-31): la guardia deve validare
    # la CLASSE dei valori validi ("finito e > 0"), non escludere di volta in
    # volta il singolo valore visto fallire (round 1-3: 0, poi <=0, poi
    # 0.0001/"nan"/"inf" ancora bypassavano). Un valore non parsabile
    # (es. "3.5" su un intero) o numericamente invalido non deve mai
    # propagare un'eccezione fuori dal modulo: si ricade sul default
    # noto-sicuro e si emette un warning (segnale collegabile a CODE-14),
    # invece di bloccare l'avvio dell'intera piattaforma unificata.
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        value = None
    if value is None or not math.isfinite(value) or value <= 0:
        logger.warning(
            "%s misconfigured, falling back to default %s: %s",
            name, default, sanitize_log_input(raw),
        )
        return default
    return value


VT_RATE_LIMIT = _parse_rate_env("VT_RATE_LIMIT", int, 4)
VT_RATE_WINDOW = _parse_rate_env("VT_RATE_WINDOW", float, 60.0)
_vt_call_times = []
_vt_rate_lock = threading.Lock()

# PERF-05: l'orchestrator smette di aspettare `/reputation` a 45 s (TIMEOUT):
# oltre quel limite il lavoro del gestore andrebbe perso, posto VT e chiamate a
# OTX e ST compresi. La scadenza della richiesta sta sotto quel limite e il
# limite dell'attesa del posto VT, lucchetto compreso, sotto la scadenza, così
# dopo un posto preso tardi c'è tempo per la chiamata. Costanti di modulo
# rilette a ogni richiesta, come DNS_DEADLINE_S (SEC-29).
REPUTATION_DEADLINE_S = 40
VT_MAX_WAIT_S = 35
REPUTATION_HTTP_TIMEOUT_S = 15
# Testi fissi di `error`. Un VT saltato non è il 404 di VT (un'osservazione): è
# una fonte non osservata, che l'orchestrator riporta dal ciclo precedente
# (COL-16), come una fonte non raggiunta entro la scadenza.
VT_SKIPPED_ERROR = "skipped: VT quota slot not available within the wait limit"
REPUTATION_DEADLINE_ERROR = "no answer within the request deadline"
# Scadenza della richiesta servita dal thread corrente: _vt_wait_for_slot() e i
# timeout delle GET la leggono da qui, non da un argomento. Fuori dal gestore non
# c'è (_check_vt chiamata da sola): l'attesa VT ha il solo limite VT_MAX_WAIT_S
# e la GET il timeout pieno.
_request_deadline = threading.local()


def _time_left():
    deadline = getattr(_request_deadline, "value", None)
    return math.inf if deadline is None else deadline - time.monotonic()


def _http_timeout():
    # PERF-05: il `timeout=` di una GET non va oltre il tempo che resta e, a
    # scadenza passata, la GET non parte: l'eccezione diventa `error` nel
    # try/except della fonte, come ogni altro guasto.
    timeout = min(REPUTATION_HTTP_TIMEOUT_S, _time_left())
    if timeout <= 0:
        raise TimeoutError(REPUTATION_DEADLINE_ERROR)
    return timeout


def _vt_wait_for_slot():
    global _vt_call_times
    # PERF-05: l'attesa si conta da qui, lucchetto compreso: chi trova la quota
    # esaurita dorme tenendo il lucchetto, quindi con N richiedenti in coda è
    # quasi tutta attesa del lucchetto. Il salto è un'eccezione e non un valore
    # di ritorno: un ritorno normale significa «posto concesso».
    give_up = time.monotonic() + min(VT_MAX_WAIT_S, _time_left())
    if not _vt_rate_lock.acquire(timeout=max(0.0, give_up - time.monotonic())):
        raise TimeoutError(VT_SKIPPED_ERROR)
    try:
        if VT_RATE_LIMIT <= 0:
            # PERF-01 (rilievo G6): con VT_RATE_LIMIT<=0 la guardia sotto
            # (`len(_vt_call_times) >= VT_RATE_LIMIT`) è sempre vera anche a
            # lista vuota, quindi si arriverebbe a `_vt_call_times[0]` su
            # lista vuota (IndexError, catturata dal try/except generico di
            # _check_vt e riportata come "list index out of range" — un
            # errore di configurazione travestito da fallimento VT reale).
            # Scelta: errore di configurazione esplicito invece di un
            # fallback silenzioso a un default, per non mascherare una env
            # var scritta male dietro un comportamento diverso da quello
            # richiesto.
            raise ValueError(f"VT_RATE_LIMIT misconfigured: must be > 0, got {VT_RATE_LIMIT}")
        if VT_RATE_WINDOW <= 0:
            # PERF-01 (G6 round 2): a finestra <= 0 il filtro sottostante
            # (`now - t < VT_RATE_WINDOW`) è sempre falso, quindi
            # _vt_call_times viene svuotata a ogni chiamata prima del
            # controllo di soglia e la guardia successiva non supera mai un
            # elemento — fail-open silenzioso, la quota VT non è più
            # limitata ma nessun errore lo segnala. Stessa scelta della
            # guardia gemella sopra: errore di configurazione esplicito
            # invece di un fallback silenzioso.
            raise ValueError(f"VT_RATE_WINDOW misconfigured: must be > 0, got {VT_RATE_WINDOW}")
        now = time.time()
        _vt_call_times = [t for t in _vt_call_times if now - t < VT_RATE_WINDOW]
        if len(_vt_call_times) >= VT_RATE_LIMIT:
            wait = VT_RATE_WINDOW - (now - _vt_call_times[0])
            # PERF-05: si dorme fino al posto o al limite, poi si riguarda la
            # finestra: se è piena, VT è saltato e quel posto non si prende più
            # (né GET né voce in _vt_call_times). Attendere fino al limite
            # invece di rinunciare subito è il disegno scelto: l'orchestrator
            # non corre sui domini seguenti a quota esaurita. Tenere il
            # lucchetto in un'attesa vana non toglie posti a nessuno: il primo
            # si libera comunque dopo il limite.
            wait = min(wait, give_up - time.monotonic())
            if wait > 0:
                time.sleep(wait)
            now = time.time()
            _vt_call_times = [t for t in _vt_call_times if now - t < VT_RATE_WINDOW]
            if len(_vt_call_times) >= VT_RATE_LIMIT:
                raise TimeoutError(VT_SKIPPED_ERROR)
        # PERF-05: il limite d'attesa vale anche quando uno scheduler in ritardo
        # fa cadere l'ingresso o il risveglio oltre `give_up`: un posto preso lì
        # supererebbe l'attesa massima e, oltre la scadenza, sarebbe consumato
        # senza GET.
        if time.monotonic() >= give_up:
            raise TimeoutError(VT_SKIPPED_ERROR)
        _vt_call_times.append(now)
    finally:
        _vt_rate_lock.release()


@app.get("/health")
def health():
    return {"status": "healthy", "service": "reputation", "version": "4.0.0",
            "sources": {"vt": bool(VT_API_KEY), "otx": bool(OTX_API_KEY), "st": bool(ST_API_KEY)}}


@router.get("/reputation", tags=["Reputation"])
def reputation_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    sources: str = Query("vt,otx,st", description="Comma-separated sources")
):
    logger.info(f"Check: {sanitize_log_input(domain)} sources={sources}")
    requested = set(s.strip() for s in sources.split(","))

    result = {
        "domain": domain, "timestamp": now_iso(),
        "virustotal": None, "otx": None, "securitytrails": None,
        "risk_score": 0, "risk_level": "unknown", "error": None
    }

    # PERF-05: le fonti in parallelo, un thread ciascuna, attese al più fino alla
    # scadenza: OTX e ST non aspettano il posto VT e i timeout non si sommano. Il
    # `timeout=` di requests non copre la risoluzione del nome né una risposta a
    # goccia, quindi la scadenza non dipende solo da quello. Una GET in corso
    # alla scadenza non si interrompe: il suo thread finisce da sé con la GET e
    # il risultato si scarta. La fonte non raggiunta è un dict a zeri con
    # `error`, mai `None` (= non richiesta o senza chiave, COL-16).
    deadline = time.monotonic() + REPUTATION_DEADLINE_S
    checks = []
    if "vt" in requested and VT_API_KEY:
        checks.append(("virustotal", _check_vt, _vt_empty))
    if "otx" in requested and OTX_API_KEY:
        checks.append(("otx", _check_otx, _otx_empty))
    if "st" in requested and ST_API_KEY:
        checks.append(("securitytrails", _check_st, _st_empty))

    def _run(check, box):
        _request_deadline.value = deadline
        box.append(check(domain))

    running = []
    for key, check, empty in checks:
        box = []
        # daemon: una GET sorda che sopravvive alla risposta non trattiene l'uscita del processo
        thread = threading.Thread(target=_run, args=(check, box), name=f"reputation-{key}", daemon=True)
        thread.start()
        running.append((key, thread, box, empty))
    for key, thread, box, empty in running:
        thread.join(max(0.0, deadline - time.monotonic()))
        result[key] = box[0] if box else dict(empty(), error=REPUTATION_DEADLINE_ERROR)

    result["risk_score"] = _calc_score(result)
    result["risk_level"] = _score_to_level(result["risk_score"])

    return JSONResponse(content=result)


# PERF-05: la forma a zeri di ogni fonte serve anche al gestore, per la fonte
# non raggiunta entro la scadenza: una sola definizione, così non divergono.
def _vt_empty():
    return {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
            "reputation": 0, "categories": {}, "error": None}


def _otx_empty():
    return {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [], "error": None}


def _st_empty():
    return {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None, "error": None}


def _check_vt(domain: str) -> dict:
    r = _vt_empty()
    try:
        _vt_wait_for_slot()  # PERF-01: attende qui, prima della chiamata, non dopo la risposta
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                            headers={"x-apikey": VT_API_KEY}, timeout=_http_timeout())
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            r["malicious"] = stats.get("malicious", 0)
            r["suspicious"] = stats.get("suspicious", 0)
            r["undetected"] = stats.get("undetected", 0)
            r["harmless"] = stats.get("harmless", 0)
            r["reputation"] = data.get("reputation", 0)
            r["categories"] = data.get("categories", {})
        elif resp.status_code == 404:
            r["error"] = VT_NOT_FOUND_ERROR
        else:
            r["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


def _check_otx(domain: str) -> dict:
    r = _otx_empty()
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                            headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=_http_timeout())
        if resp.status_code == 200:
            data = resp.json()
            r["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            r["pulse_titles"] = [p.get("name", "") for p in pulses[:5]]
            r["tags"] = list(set(t for p in pulses for t in p.get("tags", [])))[:20]
            r["malware_families"] = list(set(
                m.get("display_name", "") for p in pulses
                for m in p.get("malware_families", [])
            ))
        else:
            r["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


def _check_st(domain: str) -> dict:
    r = _st_empty()
    try:
        resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}",
                            headers={"APIKEY": ST_API_KEY}, timeout=_http_timeout())
        if resp.status_code == 200:
            data = resp.json()
            r["subdomain_count"] = data.get("subdomain_count", 0)
            r["current_dns"] = data.get("current_dns", {})
            r["alexa_rank"] = data.get("alexa_rank")
        else:
            r["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


app.include_router(router)
