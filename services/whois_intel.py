"""
WHOIS Intelligence Service (:8004)
Modulo 8 estratto — WHOIS lookup con parsing strutturato.
"""

import os, logging, subprocess, re, time, threading, json, socket, sys
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="WHOIS Intel", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("whois-intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [WHOIS] %(message)s")

WHOIS_TIMEOUT = int(os.environ.get("WHOIS_TIMEOUT", "10"))
WHOIS_DELAY = float(os.environ.get("WHOIS_DELAY", "2"))

# COL-17: testo fisso di `error` quando il lookup non restituisce alcun campo. Non
# riecheggia il testo della libreria (errno, indirizzi dei server) né l'avviso del
# registro, che può nominare indirizzi e URL.
WHOIS_NO_RECORD_ERROR = "WHOIS lookup failed: no record field was returned"

# SEC-35: testo fisso di `error` quando il figlio che interpreta la risposta scade, muore o non scrive un
# risultato leggibile. Sul modello di WHOIS_NO_RECORD_ERROR (COL-17): non riecheggia né l'output del
# figlio né il testo del registro.
WHOIS_PARSE_FAILED_ERROR = "WHOIS lookup failed: the response could not be parsed"

# SEC-35: testo fisso di `error` quando tutti i posti per i figli restano occupati oltre `WHOIS_PARSE_TIMEOUT_S`:
# il lookup non ha avuto un figlio che interpretasse la risposta. Stesso criterio di WHOIS_PARSE_FAILED_ERROR.
WHOIS_PARSE_BUSY_ERROR = "WHOIS lookup failed: too many responses are being parsed"

# SEC-35: una risposta WHOIS ostile (riga lunga, risposta enorme, server che goccia, rinvio `=xxx` senza
# fine) non deve tenere fermo il processo, che nel servizio unificato è anche quello di dashboard e login.
# Sono costanti di modulo, lette a ogni lookup, e non si configurano da ambiente: sono la soglia di sicurezza.
#
# Scadenza di tutte le connessioni insieme: un server che manda un byte ogni pochi secondi non fa mai
# scadere il timeout della singola operazione.
WHOIS_LOOKUP_DEADLINE_S = 15
# La risposta di IANA e quella del primo hop passano da regex della libreria eseguite nel processo del
# servizio, super-lineari: a 8 KB costano frazioni di secondo.
WHOIS_IANA_MAX_BYTES = 8192
WHOIS_FIRST_HOP_MAX_BYTES = 8192
# Tutto il testo letto, secondo hop compreso: è ciò che arriva al parser.
WHOIS_TOTAL_MAX_BYTES = 65536
# IANA compresa: un registro che risponde `=xxx` a ogni richiesta fa ricorrere la libreria senza fine.
WHOIS_MAX_CONNECTIONS = 5
# Limiti del figlio che fa il parsing: CPU in secondi interi (granularità di RLIMIT_CPU) e tempo di parete, che è
# anche l'attesa massima di un posto per il figlio.
WHOIS_PARSE_CPU_S = 4
WHOIS_PARSE_TIMEOUT_S = 8
# Figli vivi insieme: ognuno è un interprete con la sua memoria e la sua CPU, e una raffica di risposte ostili li
# moltiplicherebbe per il numero di richieste. I lookup in più aspettano un posto.
WHOIS_PARSE_MAX_CHILDREN = 4

# Simple LRU cache with max size
_cache = {}
_cache_order = []
CACHE_TTL = int(os.environ.get("CACHE_TTL", "86400"))
CACHE_MAX_SIZE = int(os.environ.get("CACHE_MAX_SIZE", "500"))

# Rate limiting via timestamp (non-blocking between distinct domains)
_last_query_time = 0.0
_rate_lock = threading.Lock()

# PERF-02: il turno fra due query si prenota sotto `_rate_lock` e si aspetta fuori. Prima si dormiva tenendo il
# lucchetto: le richieste concorrenti si mettevano in fila, ognuna con un thread del pool condiviso del processo
# unificato, e la k-esima aspettava circa k × WHOIS_DELAY senza limite. Chi dovrebbe aspettare più di
# WHOIS_MAX_WAIT_S risponde subito con questo errore fisso: il modulo non è raccolto e il ciclo precedente viene
# riportato, come VirusTotal senza posto nella quota (PERF-05). Caso peggiore: 12 s di turno, 15 s di lookup
# (WHOIS_LOOKUP_DEADLINE_S), 8 s di attesa di un posto per il figlio e 8 s del figlio (WHOIS_PARSE_TIMEOUT_S): 43 s,
# sotto i 45 s dell'orchestrator. Turno e ultima query sull'orologio monotono: un salto all'indietro dell'orologio
# di sistema bloccherebbe le query per tutta la durata del salto. Costante di modulo, come le soglie di SEC-35.
WHOIS_MAX_WAIT_S = 12
WHOIS_RATE_BUSY_ERROR = "WHOIS lookup skipped: no query slot within the wait limit"

try:
    import whois as whois_lib
    HAS_WHOIS_LIB = True
except ImportError:
    HAS_WHOIS_LIB = False


@app.get("/health")
def health():
    return {"status": "healthy", "service": "whois-intel", "version": "4.0.0",
            "whois_lib": HAS_WHOIS_LIB}


@router.get("/whois", tags=["WHOIS Intelligence"])
def whois_check(domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")):
    logger.info(f"Check: {sanitize_log_input(domain)}")

    # Cache check
    cached = _cache.get(domain)
    if cached and (time.time() - cached["_cached_at"]) < CACHE_TTL:
        logger.info(f"Cache hit: {sanitize_log_input(domain)}")
        return JSONResponse(content=cached["data"])

    result = {
        "domain": domain, "timestamp": now_iso(),
        "registrar": None, "creation_date": None, "expiration_date": None,
        "updated_date": None, "status": [], "nameservers": [],
        "registrant": {"name": None, "org": None, "country": None, "email": None},
        "privacy_protected": False, "dnssec": False,
        "age_days": None, "error": None
    }

    # Rate limiting: only wait the remaining time since last real query
    global _last_query_time
    with _rate_lock:
        now = time.monotonic()
        turn = max(now, _last_query_time + WHOIS_DELAY)
        wait = turn - now
        if wait <= WHOIS_MAX_WAIT_S:
            _last_query_time = turn
    if wait > WHOIS_MAX_WAIT_S:
        # Come WHOIS_PARSE_BUSY_ERROR: dipende dal carico del momento, non dal dominio, quindi niente cache.
        logger.warning(f"WHOIS: nessun turno entro {WHOIS_MAX_WAIT_S}s per {sanitize_log_input(domain)}")
        result["error"] = WHOIS_RATE_BUSY_ERROR
        return JSONResponse(content=result)
    if wait > 0:
        time.sleep(wait)

    try:
        if HAS_WHOIS_LIB:
            w = _whois_library_lookup(domain)
            result["registrar"] = _str(w.registrar)
            result["creation_date"] = _norm_date(w.creation_date)
            result["expiration_date"] = _norm_date(w.expiration_date)
            result["updated_date"] = _norm_date(w.updated_date)
            result["status"] = _to_list(w.status)
            result["nameservers"] = [ns.lower() for ns in _to_list(w.name_servers)] if w.name_servers else []
            result["registrant"]["name"] = _str(getattr(w, "name", None))
            result["registrant"]["org"] = _str(getattr(w, "org", None))
            result["registrant"]["country"] = _str(getattr(w, "country", None))
            result["registrant"]["email"] = _str(getattr(w, "emails", None))
            result["dnssec"] = str(getattr(w, "dnssec", "")).lower() not in ("", "unsigned", "none")
        else:
            result = _whois_cli_fallback(domain, result)

        # COL-17: se il server del registro non risponde, risponde vuoto o oppone un limite di
        # richieste la libreria non solleva: restituisce un oggetto con ogni campo `None`. Con
        # `error` nullo sarebbe un'osservazione valida e sostituirebbe la baseline invece di
        # farla riportare (COL-13, CODE-23). Il controllo sta sul risultato finale, quindi vale
        # per entrambi i rami; sollevare qui riusa forma e log del ramo d'eccezione e salta le
        # inferenze, che dal registrante assente dedurrebbero `privacy_protected`.
        if not _has_observed_field(result):
            # Gli unici campi non osservati che il lookup può aver valorizzato.
            result["registrant"]["email"] = None
            result["dnssec"] = False
            raise LookupError(WHOIS_NO_RECORD_ERROR)

        # Inferenze
        reg_name = (result["registrant"]["name"] or "").lower()
        reg_org = (result["registrant"]["org"] or "").lower()
        privacy_keywords = ["privacy", "redacted", "withheld", "whoisguard",
                            "domains by proxy", "contact privacy", "identity protection"]
        result["privacy_protected"] = any(
            kw in reg_name or kw in reg_org for kw in privacy_keywords
        ) or (not result["registrant"]["name"] and not result["registrant"]["org"])

        if result["creation_date"]:
            try:
                created = datetime.fromisoformat(result["creation_date"])
                result["age_days"] = (datetime.now(timezone.utc) - created).days
            except (ValueError, TypeError):
                pass

    except Exception as e:
        result["error"] = sanitize_error(e)
        logger.error(f"Errore WHOIS {sanitize_log_input(domain)}: {e}")

    # SEC-35: restare senza posto per il figlio dipende dal carico di quel momento, non dal dominio: in cache lo
    # stesso errore durerebbe `CACHE_TTL` anche a posti liberi. Ogni altro esito, errori di raccolta compresi, resta.
    if result["error"] == WHOIS_PARSE_BUSY_ERROR:
        return JSONResponse(content=result)

    # Cache store with LRU eviction
    if len(_cache) >= CACHE_MAX_SIZE:
        oldest = _cache_order.pop(0)
        _cache.pop(oldest, None)
    _cache[domain] = {"data": result, "_cached_at": time.time()}
    if domain in _cache_order:
        _cache_order.remove(domain)
    _cache_order.append(domain)

    return JSONResponse(content=result)


def _whois_cli_fallback(domain: str, result: dict) -> dict:
    try:
        proc = subprocess.run(["whois", domain], capture_output=True, text=True,
                              timeout=WHOIS_TIMEOUT + 5)
        raw = proc.stdout
        result["registrar"] = _extract(raw, r"Registrar:\s*(.+)")
        result["creation_date"] = _extract(raw, r"Creation Date:\s*(.+)")
        result["expiration_date"] = _extract(raw, r"Expir\w+ Date:\s*(.+)")
        result["updated_date"] = _extract(raw, r"Updated Date:\s*(.+)")
        ns_matches = re.findall(r"Name Server:\s*(\S+)", raw, re.IGNORECASE)
        result["nameservers"] = [ns.lower().rstrip(".") for ns in ns_matches]
        status_matches = re.findall(r"Domain Status:\s*(\S+)", raw, re.IGNORECASE)
        result["status"] = status_matches
    except Exception as e:
        result["error"] = f"CLI fallback: {e}"
    return result


class _LookupBudget:
    """Il budget di UN lookup, condiviso da tutte le sue connessioni (IANA, registro, registrar, rinvii
    `=xxx`). Le costanti di modulo si leggono qui e nei metodi, a ogni lookup."""

    def __init__(self):
        self.deadline = time.monotonic() + WHOIS_LOOKUP_DEADLINE_S
        self.bytes_left = WHOIS_TOTAL_MAX_BYTES
        self.connections_left = WHOIS_MAX_CONNECTIONS
        self.registry = None

    def byte_cap(self, host: str) -> int | None:
        """Tetto di byte della singola connessione, `None` se vale solo quello totale. Hanno un tetto proprio
        IANA e il registro (la connessione che segue IANA o apre il lookup, `=xxx` compresi): la libreria ne passa
        il testo a regex nel processo. Il secondo hop va solo al parser, che gira nel figlio."""
        host = host.lower()
        if host == whois_lib.NICClient.IANAHOST:    # lo stesso host che apre `NICClient.findwhois_iana`
            return WHOIS_IANA_MAX_BYTES
        if self.registry is None:
            self.registry = host
        return WHOIS_FIRST_HOP_MAX_BYTES if host == self.registry else None


class _BudgetedSocket:
    """Il socket di `NICClient` con il budget del lookup. Espone solo ciò che la libreria usa. Scadenza e
    connessioni esaurite sollevano un `OSError`, che la libreria tratta come un guasto di rete; i byte oltre
    il tetto non sono un errore: `recv` ritorna vuoto come a fine flusso e la libreria tiene il testo letto."""

    def __init__(self, sock, budget: _LookupBudget):
        self._sock, self._budget = sock, budget
        self._op_timeout = None     # il timeout che la libreria chiede per ogni operazione
        self._bytes_left = None     # byte residui di questa connessione; None = vale solo il tetto totale

    def settimeout(self, seconds):
        self._op_timeout = seconds

    def _arm(self):
        """A ogni operazione: il timeout della libreria, ridotto al tempo che resta al lookup."""
        remaining = self._budget.deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("whois lookup deadline exceeded")
        self._sock.settimeout(remaining if self._op_timeout is None else min(self._op_timeout, remaining))

    def connect(self, address):
        budget = self._budget
        if budget.connections_left <= 0:
            raise OSError("whois lookup connection limit exceeded")
        budget.connections_left -= 1
        self._bytes_left = budget.byte_cap(address[0])
        self._arm()
        return self._sock.connect(address)

    def send(self, data):
        self._arm()
        return self._sock.send(data)

    def recv(self, size):
        budget = self._budget
        room = budget.bytes_left if self._bytes_left is None else min(budget.bytes_left, self._bytes_left)
        if room <= 0:
            return b""
        self._arm()
        data = self._sock.recv(min(size, room))
        budget.bytes_left -= len(data)
        if self._bytes_left is not None:
            self._bytes_left -= len(data)
        return data

    def close(self):
        return self._sock.close()


if HAS_WHOIS_LIB:
    class _BudgetedNICClient(whois_lib.NICClient):
        """`NICClient` i cui socket rispondono al budget del lookup: IANA, registro, registrar e rinvii."""

        def __init__(self, budget: _LookupBudget):
            super().__init__()
            self._budget = budget

        def get_socket(self):
            # Delega a `NICClient.get_socket`, che costruisce il socket vero (SOCKS compreso): i test lo
            # sostituiscono sulla classe base e deve continuare a valere.
            return _BudgetedSocket(super().get_socket(), self._budget)


def _whois_library_lookup(domain: str) -> SimpleNamespace:
    """Ciò che fa `whois_lib.whois(domain)`, nei suoi due passi pubblici con i limiti di SEC-35: la rete nel
    processo con un budget, il parsing in un figlio. Ritorna un oggetto con i soli attributi che il servizio legge."""
    domain = whois_lib.extract_domain(domain)
    # Senza `quiet`, come `whois_lib.whois(domain)`: il servizio registra l'esito di un lookup fallito, non la causa,
    # e la riga della libreria è l'unica che la porta. Il testo che registra è quello dell'eccezione del socket
    # (del sistema operativo o fisso del budget), non dati del registro.
    text = _BudgetedNICClient(_LookupBudget()).whois_lookup(None, domain.encode("idna"), 0)
    return _parse_in_child(domain, text)


# Codice del figlio che interpreta il testo. Le regex dei parser di python-whois sono super-lineari e tengono il
# GIL: nel processo del servizio fermerebbero anche dashboard e login, in un figlio si limitano con RLIMIT_CPU e
# si uccidono. `-I` e una stringa invece di un modulo: il figlio ignora le variabili PYTHON* e non mette la
# directory corrente in `sys.path`.
# RLIMIT_CORE a 0 perché SIGXCPU, azione predefinita, scrive un core con il testo della risposta; il limite
# rigido a +1 s uccide il figlio anche se il segnale fosse ignorato. `os.nice(10)` perché il parsing, fino al limite
# di CPU, non tolga tempo al servizio: è equità, non una barriera, e se il sistema lo rifiuta il figlio prosegue;
# i limiti sopra sono obbligatori. Risponde con un solo JSON: i valori che il servizio legge (le date come testo
# ISO, che `_norm_date` tratta come un `datetime`), oppure classe e testo dell'eccezione del parser, troncato a 1024
# caratteri: `sanitize_error` redige i percorsi e poi taglia a 200 più «...», quindi un taglio più corto lascerebbe
# un percorso a metà; il tetto tiene limitato il testo che il servizio elabora.
_PARSE_CHILD = '''
import datetime, json, os, resource, sys
cpu = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
try:
    os.nice(10)
except OSError:
    pass
request = json.loads(sys.stdin.buffer.read())
def encode(value):
    return value.isoformat() if isinstance(value, datetime.datetime) else str(value)
try:
    from whois.parser import WhoisEntry
    entry = WhoisEntry.load(request["domain"], request["text"])
    reply = {"fields": {name: getattr(entry, name, None) for name in (
        "registrar", "creation_date", "expiration_date", "updated_date", "status", "name_servers",
        "name", "org", "country", "emails", "dnssec")}}
except Exception as exc:
    reply = {"error": {"type": type(exc).__name__, "text": str(exc)[:1024]}}
sys.stdout.write(json.dumps(reply, default=encode))
'''


# Il figlio interpreta testo di terzi e non ha bisogno delle credenziali del servizio (password, token, chiavi API
# stanno nel suo ambiente, leggibili in `/proc/<pid>/environ`): riceve solo queste variabili, se il servizio le ha.
_PARSE_CHILD_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "LD_LIBRARY_PATH")

# Figli vivi e chi aspetta un posto. Tetto e attesa si leggono a ogni acquisizione, quindi non un
# `BoundedSemaphore` costruito all'import, che fisserebbe lì il numero di posti.
_parse_seats = threading.Condition()
_parse_alive = 0


def _take_parse_seat() -> bool:
    """Prende un posto per un figlio, aspettando al più `WHOIS_PARSE_TIMEOUT_S`. Con un posto libero non aspetta."""
    global _parse_alive
    with _parse_seats:
        if not _parse_seats.wait_for(lambda: _parse_alive < WHOIS_PARSE_MAX_CHILDREN, WHOIS_PARSE_TIMEOUT_S):
            return False
        _parse_alive += 1
        return True


def _free_parse_seat():
    global _parse_alive
    with _parse_seats:
        _parse_alive -= 1
        _parse_seats.notify_all()


def _parse_in_child(domain: str, text: str) -> SimpleNamespace:
    """`WhoisEntry.load(domain, text)` in un figlio. Un'eccezione del parser risale con il suo testo (troncato
    a 1024 caratteri), come se fosse sollevata qui; se il figlio non parte, scade, muore o non scrive un risultato
    leggibile l'esito è un errore di raccolta con un testo fisso, mai ciò che il figlio ha scritto. Senza un posto
    entro `WHOIS_PARSE_TIMEOUT_S` il figlio non viene lanciato e l'esito è `WHOIS_PARSE_BUSY_ERROR`."""
    request = json.dumps({"domain": domain, "text": text}).encode()
    env = {name: os.environ[name] for name in _PARSE_CHILD_ENV if name in os.environ}
    if not _take_parse_seat():
        raise LookupError(WHOIS_PARSE_BUSY_ERROR)
    try:    # il posto torna libero a ogni esito, ma solo dopo che il figlio è stato atteso: finché esiste pesa
        with subprocess.Popen([sys.executable, "-I", "-c", _PARSE_CHILD, str(WHOIS_PARSE_CPU_S)], env=env,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                stdout, _ = child.communicate(input=request, timeout=WHOIS_PARSE_TIMEOUT_S)
            except BaseException:
                child.kill()    # il figlio non resta vivo; l'uscita dal `with` lo attende, nessuno zombie
                raise
    except (OSError, subprocess.TimeoutExpired):
        raise LookupError(WHOIS_PARSE_FAILED_ERROR) from None
    finally:
        _free_parse_seat()
    if child.returncode != 0:
        raise LookupError(WHOIS_PARSE_FAILED_ERROR)
    try:
        reply = json.loads(stdout)
        if "error" in reply:
            message = reply["error"]["text"]
        else:
            return SimpleNamespace(**reply["fields"])
    except (ValueError, KeyError, TypeError):
        raise LookupError(WHOIS_PARSE_FAILED_ERROR) from None
    raise LookupError(message)


def _has_observed_field(result: dict) -> bool:
    """True se il lookup ha restituito almeno un campo che descrive il dominio. Non contano
    `registrant.email` (la libreria raccoglie in `emails` qualunque indirizzo del testo, anche
    quello di un avviso del registro) né `dnssec`, `privacy_protected` e `age_days`, dedotti."""
    registrant = result["registrant"]
    return any((result["registrar"], result["creation_date"], result["expiration_date"],
                result["updated_date"], result["status"], result["nameservers"],
                registrant["name"], registrant["org"], registrant["country"]))


def _str(val) -> str | None:
    if val is None: return None
    if isinstance(val, list): return str(val[0]) if val else None
    return str(val).strip() or None


def _norm_date(val) -> str | None:
    if val is None: return None
    if isinstance(val, list): val = val[0]
    if isinstance(val, datetime): return val.isoformat()
    return str(val).strip() or None


def _to_list(val) -> list:
    if val is None: return []
    if isinstance(val, list): return val
    return [val]


def _extract(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else None

app.include_router(router)
