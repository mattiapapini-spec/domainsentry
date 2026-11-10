"""
Shared utilities — funzioni comuni a tutti i microservizi.
Estratte dal monolite v3.1.
"""

import subprocess
import hashlib
import ssl
import re
import sys
import time
import logging
import socket
import math
import bisect
import threading
import types
import os as _os
from datetime import datetime, timezone, timedelta
from html.parser import HTMLParser

from shared.constants import VT_NOT_FOUND_ERROR

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

logger = logging.getLogger("shared")


# ═══════════════════════════════════════════════════════════════
# SSRF PROTECTION
# ═══════════════════════════════════════════════════════════════
import ipaddress
from urllib.parse import urlparse, urljoin as _urljoin

# Allow opting out in trusted/offline labs, but default is SAFE (block internal).
SSRF_PROTECTION = _os.environ.get("SSRF_PROTECTION", "true").lower() != "false"

# CODE-15+CODE-14 (G3 terzo giro, requisito 3): unica fonte di verità per i due
# prefissi che `http_get_with_retry` scrive su `error` quando il guard SSRF
# scatta — un blocco diretto (riga ~112) e uno su un hop di redirect (righe
# ~134/157). Sono due stringhe distinte, non una: "blocked redirect..." non
# inizia per "blocked (SSRF protection)". `collection_failed` le consuma
# entrambe più sotto; prima di questa costante erano duplicate a mano nei tre
# punti produttori e nel consumatore.
SSRF_ERROR_PREFIX = "blocked (SSRF protection)"
SSRF_REDIRECT_ERROR_PREFIX = "blocked redirect (SSRF protection)"


# Reti che `is_private` non copre: CGNAT (comprende un endpoint di metadati
# cloud) e il relay 6to4 anycast, non instradabile su Internet.
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.88.99.0/24"),
)


def _is_blocked_ip(ip_str: str) -> bool:
    """True if an IP is private, loopback, link-local, or otherwise internal —
    the targets an SSRF attack would aim for (cloud metadata 169.254.169.254,
    localhost, RFC1918 ranges, the internal Docker network, etc.)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block, fail closed
    # Un IPv4 mappato in IPv6 (::ffff:a.b.c.d) si giudica dall'IPv4
    # incapsulato: le proprietà `is_*` dell'indirizzo mappato danno esiti
    # diversi da una versione di Python all'altra.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or
        ip.is_reserved or ip.is_multicast or ip.is_unspecified or
        any(ip in net for net in _EXTRA_BLOCKED_NETWORKS) or
        ip_str == "169.254.169.254"  # cloud metadata (explicit)
    )


def is_safe_url(url: str) -> tuple[bool, str]:
    """Resolve the URL's host and verify it does NOT point at an internal address.
    Returns (safe, reason). Used to gate outbound fetches against SSRF."""
    if not SSRF_PROTECTION:
        return True, "ssrf-protection-disabled"
    try:
        host = urlparse(url).hostname
        if not host:
            return False, "no host in URL"
        # Resolve ALL addresses the host maps to; block if ANY is internal
        # (defends against DNS that returns both a public and an internal A record).
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if _is_blocked_ip(ip):
                return False, f"host {host} resolves to internal address {ip}"
        return True, "ok"
    except socket.gaierror:
        return False, "host does not resolve"
    except Exception as e:
        return False, f"url validation failed: {e}"


# SEC-26: `fqdn` finisce come argomento posizionale di `dig`, che legge `@host`
# come server da interrogare e `-x` / `+opt` come opzioni. Senza shell non c'è
# injection di comandi, ma la sintassi di `dig` basta a dirottare la query su un
# server scelto da chi chiama. Si ammette solo un nome DNS: primo carattere
# alfanumerico o `_` (`_dmarc.`, `_domainkey.`), poi `[A-Za-z0-9_.-]`, al più 253.
# Si usa `fullmatch`: `match` con `$` accetterebbe un `\n` finale.
_DIG_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


def dig_query(fqdn: str, rtype: str, timeout: int = 10) -> list[str]:
    try:
        # Dentro il `try`: un `fqdn` non-stringa resta un "ERROR" in lista come
        # prima, non un'eccezione per il chiamante. Il nome rifiutato non viene
        # riecheggiato nell'errore (può contenere newline o caratteri di controllo).
        if len(fqdn) > 253 or not _DIG_NAME_RE.fullmatch(fqdn):
            return ["ERROR: invalid DNS name"]
        proc = subprocess.run(
            ["dig", "+short", "+ndots=1", f"+time={timeout}", "+tries=2",
             "+noidnout", fqdn, rtype],
            capture_output=True, text=True, timeout=timeout + 10)
        # COL-08: `dig` scrive le proprie diagnostiche su stdout (`;; communications
        # error …`, `;; no servers could be reached`) anche con `+short`. Un rc != 0
        # (9 nessuna risposta, 10 errore fatale, 1 uso) è "non si è potuto sapere",
        # come il timeout: errore, non record. Lo stdout non si riecheggia.
        if proc.returncode != 0:
            return [f"ERROR: dig exited with code {proc.returncode}"]
        # Con rc 0 una risposta non parsabile esce come `;; Got bad packet: <motivo>`
        # seguita da `N bytes` e da un dump esadecimale che NON inizia con `;`: il
        # filtro sotto lo lascerebbe passare come record. Non è una risposta: errore.
        if any(ln.lstrip().startswith(";; Got bad packet") for ln in proc.stdout.split("\n")):
            return ["ERROR: dig got an unparseable response"]
        # Le altre righe `;` con rc 0 (es. primo tentativo perso) affiancano una
        # risposta vera: in presentation format nessun rdata inizia con `;` (TXT e
        # CAA escono tra virgolette), quindi si scartano senza toccare i record.
        lines = [ln.strip().rstrip(".") for ln in proc.stdout.strip().split("\n")
                 if ln.strip() and not ln.lstrip().startswith(";")]
        return sorted(lines)
    except FileNotFoundError:
        return ["ERROR: dig not found"]
    except subprocess.TimeoutExpired:
        return ["ERROR: timeout"]
    except Exception as e:
        return [f"ERROR: {e}"]


def is_valid(records: list[str]) -> bool:
    return bool(records) and records[0] != "" and not records[0].startswith("ERROR")


# RES-01: `+short` non stampa lo `status:` della risposta, quindi NODATA, NXDOMAIN,
# SERVFAIL, REFUSED… escono tutti come stdout vuoto e rc 0 (`[]`). `dig_lookup`
# chiede la testata (`+comments`) e le sole righe di risposta (`+noall +answer`,
# ridotte a `owner TYPE rdata` da `+nottlid +noclass`). Le due righe lette hanno lo
# stesso testo in dig 9.16/9.18/9.20 e si ancorano a inizio riga: nel presentation
# format un owner o un rdata che le imitasse non inizia mai per `;` (un TXT/CAA
# esce tra virgolette, una label con `;` come `\;`), quindi resta un record.
_DIG_HEADER_RE = re.compile(r";; ->>HEADER<<- opcode: QUERY, status: ([A-Za-z0-9_]+), id: [0-9]+")
_DIG_FLAGS_RE = re.compile(r";; flags:[^;]*; QUERY: [0-9]+, ANSWER: ([0-9]+),")


def dig_lookup(fqdn: str, rtype: str, timeout: int = 10, *, limit: float | None = None) -> tuple[str, list[str]]:
    """(stato, record) di una query. Stato: `ok` (NOERROR con record), `nodata`
    (NOERROR senza), `nxdomain`, oppure `unknown` = "non si è potuto sapere": non è
    un dato sul dominio e porta sempre record `[]`. Lista bianca: ogni rcode diverso
    da NOERROR/NXDOMAIN (SERVFAIL, REFUSED, YXDOMAIN, token mai visti…) è `unknown`.
    `limit` (SEC-29): secondi al massimo per l'intera chiamata (None: `timeout + 10`).
    Allo scadere `subprocess.run` uccide `dig` e ne attende la fine: la query è
    `unknown`. Senza tempo residuo nessun processo parte. `limit` non entra nell'argv:
    `dig` accetta solo `+time` interi, e con un valore frazionario esce senza query."""
    try:
        # Dentro il `try` come in `dig_query`: un `fqdn` non-stringa è `unknown`, non
        # un'eccezione per il chiamante. Guardia di SEC-26 (`@host`, `-x`, `+opt`).
        if len(fqdn) > 253 or not _DIG_NAME_RE.fullmatch(fqdn):
            return "unknown", []
        # `not limit > 0` e non `limit <= 0`: anche un NaN vale "nessun tempo residuo".
        if limit is not None and not limit > 0:
            return "unknown", []
        proc = subprocess.run(
            ["dig", "+noall", "+comments", "+answer", "+nottlid", "+noclass",
             "+ndots=1", f"+time={timeout}", "+tries=2", "+noidnout", fqdn, rtype],
            capture_output=True, text=True, timeout=timeout + 10 if limit is None else min(timeout + 10, limit))
        # Come COL-08: rc != 0 (9 nessuna risposta, 10 errore fatale) non è una risposta.
        if proc.returncode != 0:
            return "unknown", []
        headers, flags, answers = [], [], []
        for raw in proc.stdout.split("\n"):
            ln = raw.strip()
            if not ln:
                continue
            if not ln.startswith(";"):
                answers.append(ln)
            # Con rc 0 un pacchetto non parsabile esce come `;; Got bad packet` (il
            # dump esadecimale seguente non inizia per `;`), e un TXT malformato come
            # `;; Warning: Message parser…` con la testata `ANSWER: 1` e nessuna riga:
            # con `+short` era NODATA. Nessuno dei due è una risposta.
            elif ln.startswith((";; Got bad packet", ";; Warning: Message parser reports malformed")):
                return "unknown", []
            else:
                header = _DIG_HEADER_RE.fullmatch(ln)
                if header:
                    headers.append(header.group(1))
                flag = _DIG_FLAGS_RE.match(ln)
                if flag:
                    flags.append(int(flag.group(1)))
        # Fail-closed: senza esattamente una testata e una riga `flags` (stdout di
        # `+short`, due risposte concatenate…) lo stato non è leggibile, e ricadere sul
        # vecchio parsing farebbe di nuovo diventare un guasto un dato (COL-08).
        # `ANSWER: N` contro le righe smaschera una risposta troncata o malformata.
        if len(headers) != 1 or len(flags) != 1 or len(answers) != flags[0]:
            return "unknown", []
        records = []
        for ln in answers:
            fields = ln.split(None, 2)
            if len(fields) < 3:
                return "unknown", []
            records.append(fields[2].strip().rstrip("."))
        if headers[0] == "NOERROR":
            return ("ok" if records else "nodata"), sorted(records)
        if headers[0] == "NXDOMAIN":
            # Resta l'eventuale catena di CNAME, come con `+short`.
            return "nxdomain", sorted(records)
        return "unknown", []
    except Exception:
        # Niente `{e}` nel risultato (a differenza di `dig_query`): FileNotFoundError,
        # TimeoutExpired, stdout non decodificabile valgono tutti "non so".
        return "unknown", []


def dns_unknown_rtypes(dns) -> set[str]:
    """Tipi di record di una sezione `dns` con `records_status == "unknown"`.
    Uno stato mancante o malformato conta come noto: gli snapshot su disco precedenti
    a RES-01 non lo hanno e devono leggersi come prima. Non solleva mai: i chiamanti
    ricevono JSON di altri servizi e file su disco."""
    status = dns.get("records_status") if isinstance(dns, dict) else None
    if not isinstance(status, dict):
        return set()
    return {rtype for rtype, value in status.items() if value == "unknown"}


# ═══════════════════════════════════════════════════════════════
# HTTP
# ═══════════════════════════════════════════════════════════════

# SEC-16: cap di default sulla dimensione del body scaricato da
# `http_get_with_retry` — zona non autenticata (`/http`), body
# attacker-controlled, nessun limite prima di questo fix (DoS confermato:
# 16,44s wall-clock per una singola /http). Pattern coerente con
# `shared/security.py:15` (MAX_BODY_SIZE) e `services/cert_intel.py:20`
# (MAX_CRTSH_BYTES): costante di modulo, letta a runtime via
# `_os.environ.get` (non bindata come default-arg), così un monkeypatch a
# runtime (test) e il parametro `max_bytes` sotto (per chiamanti con un
# host fisso e fidato, es. crt.sh, che serve un cap più permissivo) restano
# entrambi efficaci.
MAX_FETCH_BODY_BYTES = int(_os.environ.get("MAX_FETCH_BODY_BYTES", str(2 * 1024 * 1024)))

# SEC-18: durata massima dell'INTERA chiamata a `http_get_with_retry` —
# tentativi, redirect, backoff e fase degli header inclusi. `timeout=` di
# `requests`/`urlopen` vale per singola operazione sul socket e si riarma a
# ogni byte ricevuto: un server a goccia (1 byte ogni pochi secondi) teneva
# occupato il thread per ore, in zona non autenticata (`/http`). 40s sta sotto
# i 45s di SERVICE_TIMEOUT dell'orchestrator, oltre i quali la pipeline scarta
# comunque il risultato. Letta a runtime come MAX_FETCH_BODY_BYTES; il
# parametro `max_seconds` per chiamante ha la precedenza (anche verso l'alto).
# Prefisso distinto da quelli SSRF: `collection_failed` deve leggere la
# scadenza come "non ho potuto guardare", non come un fatto sul dominio.
FETCH_DEADLINE_ERROR_PREFIX = "fetch deadline exceeded"


def _finite_positive_seconds(name, raw, default):
    # Stesso principio di PERF-01 (`_parse_rate_env`, services/reputation.py):
    # si valida la CLASSE dei valori ammessi ("numero finito > 0"), non il
    # singolo valore visto fallire. `shared.utils` è importato da tutti i
    # servizi: un refuso nell'env non deve impedirne l'avvio, ma ricadere sul
    # default dichiarandolo. Una sola regola per env e parametro
    # `max_seconds`: un valore non valido non deve essere né una scadenza
    # immediata (0, negativo, nan) né un limite tolto (inf). `%r` al posto di
    # sanitize_log_input per non far importare `shared.security` (e
    # starlette) a questo modulo: repr() neutralizza newline e caratteri di
    # controllo.
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = None
    if value is None or not math.isfinite(value) or value <= 0:
        logger.warning("%s misconfigured, falling back to default %s: %r", name, default, raw)
        return default
    return value


def _parse_fetch_seconds_env(name, default):
    raw = _os.environ.get(name)
    return default if raw is None else _finite_positive_seconds(name, raw, default)


MAX_FETCH_SECONDS = _parse_fetch_seconds_env("MAX_FETCH_SECONDS", 40)


class _SSRFConnectBlocked(Exception):
    """Indirizzo bloccato dalla guardia al connect (`create_connection`). Non è
    un OSError di proposito: urllib3 e `urllib` convertono ogni OSError in un
    errore di connessione ritentabile, questo deve invece attraversarli e
    chiudere la chiamata senza retry, come la guardia per nome."""


class _FetchDeadline:
    """Orologio unico di una chiamata a `http_get_with_retry` + watchdog.

    La richiesta resta sul thread del chiamante: il watchdog gira in un thread
    proprio che non esegue I/O, quindi nessun lavoro viene abbandonato. Allo
    scadere chiude (`shutdown`) i socket tracciati, il che sveglia la `recv`
    bloccata del chiamante: è l'unico modo di interrompere header o body a
    goccia, perché nessun timeout per operazione si accumula (e
    `urllib3.Timeout(total=)` fissa `settimeout` una volta sola)."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.expires = time.monotonic() + seconds
        self.fired = False
        self._socks = []
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._watch, name="fetch-deadline", daemon=True)
        self._thread.start()

    def remaining(self):
        return self.expires - time.monotonic()

    def expired(self):
        return self.fired or self.remaining() <= 0

    def clamp(self, timeout):
        """Timeout per operazione, mai oltre il tempo che resta: connect e
        handshake TLS non sono interrompibili dal watchdog (il socket non è
        ancora raggiungibile) e si fermano solo sul proprio timeout."""
        left = self.remaining()
        if left <= 0:
            raise TimeoutError(FETCH_DEADLINE_ERROR_PREFIX)
        # `requests` accetta anche `(connect, read)` e `urllib3.util.Timeout`
        # (HEAD li passava a `requests.get` così com'erano): ogni componente
        # va limitato al residuo, altrimenti `min()` solleva TypeError.
        if isinstance(timeout, tuple):
            return tuple(self.clamp(part) for part in timeout)
        if hasattr(timeout, "clone"):
            # `Timeout` (riconosciuto per `clone` e non per isinstance: il
            # modulo si importa anche senza urllib3). Si limita `total` e non
            # i componenti: urllib3 ne deriva da solo connect e read, anche
            # quando valgono None, e per il read sottrae il tempo già speso.
            limited = timeout.clone()
            limited.total = left if limited.total is None else min(limited.total, left)
            return limited
        # `timeout=None` = nessun limite per singola operazione (contratto
        # precedente a SEC-18): l'unico limite è il residuo.
        return left if timeout is None else min(timeout, left)

    def create_connection(self, address, timeout, source_address=None, socket_options=None,
                          guard=True):
        """`socket.create_connection` col residuo ricalcolato a OGNI indirizzo.
        Le versioni di urllib3 e http.client, che questa sostituisce, provano
        tutti gli indirizzi di `getaddrinfo` con il timeout intero: con N
        record A morti la chiamata dura N x timeout, e N lo decide chi
        controlla il DNS del lookalike. Qui il ciclo si ferma appena il
        residuo finisce, e dopo il connect il timeout del socket (che
        l'handshake TLS eredita per intero) scende al residuo di quel momento,
        non a quello di inizio tentativo.

        `guard=False` per la connessione a un proxy configurato dall'operatore."""
        host, port = address
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        # Difesa in profondità rispetto alla guardia per nome (`is_safe_url`):
        # qui si valida ogni indirizzo che si sta davvero per contattare, prima
        # del primo connect. Come in `is_safe_url`, uno solo bloccato blocca
        # l'host intero, anche se gli altri sono pubblici.
        if guard and SSRF_PROTECTION:
            for info in infos:
                if _is_blocked_ip(info[4][0]):
                    raise _SSRFConnectBlocked(f"host {host} resolves to internal address {info[4][0]}")
        err = None
        for af, socktype, proto, _canon, sa in infos:
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                for opt in socket_options or ():
                    sock.setsockopt(*opt)
                sock.settimeout(self.clamp(timeout))
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                sock.settimeout(self.clamp(timeout))
                return sock
            except OSError as exc:
                err = exc
                if sock is not None:
                    sock.close()
                if self.remaining() <= 0:
                    break
        raise err or OSError("getaddrinfo returns an empty list")

    def sleep(self, seconds):
        """Backoff che non supera il tempo che resta: al risveglio il tentativo
        successivo trova la scadenza invece di partire oltre il limite."""
        time.sleep(max(min(seconds, self.remaining()), 0))

    def track(self, conn):
        """Registra il socket di `conn` un attimo prima che legga la risposta.
        Lì connect e handshake sono finiti e `conn.sock` è il socket
        definitivo. Si tiene il socket e non `conn`: `urllib` azzera
        `conn.sock` dopo `getresponse`, ma il body si legge dallo stesso socket."""
        getresponse = conn.getresponse

        def _getresponse(*args, **kwargs):
            if conn.sock is not None:
                with self._lock:
                    self._socks.append(conn.sock)
            return getresponse(*args, **kwargs)

        conn.getresponse = _getresponse
        return conn

    def _watch(self):
        # TIMEOUT_MAX: un `seconds` finito ma enorme (es. 1e300) farebbe
        # sollevare OverflowError a `wait` e lascerebbe la chiamata senza controllo.
        if self._done.wait(min(self.seconds, threading.TIMEOUT_MAX)):
            return
        self.fired = True
        # Dopo la scadenza si continua a chiudere ogni 50ms: un socket
        # registrato in ritardo (connect/handshake terminati oltre il limite)
        # non deve poter ripartire con una nuova goccia.
        while True:
            with self._lock:
                socks = list(self._socks)
            for sock in socks:
                # Il watchdog non deve mai morire: un'eccezione qui lascerebbe
                # il limite disattivato in silenzio (fallisce aperto).
                try:
                    if sock.fileno() == -1:
                        continue  # già chiuso dal chiamante: nessuna syscall a ogni giro
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except (OSError, ValueError):
                        pass  # già spento o non connesso
                    except Exception:
                        # Senza `shutdown()` (es. SSLTransport, TLS-in-TLS via
                        # proxy HTTPS): `close()` è il meglio che resta, e gli
                        # altri socket vanno comunque chiusi.
                        sock.close()
                except Exception:
                    pass
            if self._done.wait(0.05):
                return

    def close(self):
        self._done.set()
        self._thread.join(1)


def _fetch_deadline_result(result, deadline):
    # Allo scadere non resta nulla di parziale, nemmeno lo status di un
    # tentativo o hop precedente (es. il 503 del primo tentativo): un check con
    # `status_code` valorizzato conta come lettura reale per `collection_failed`
    # e avvelenerebbe la baseline (classe CODE-01).
    result.update({"status_code": None, "content": None, "headers": {}, "final_url": None,
                   "error": f"{FETCH_DEADLINE_ERROR_PREFIX}: {deadline.seconds:g}s"})
    return result


def _bound_connect(deadline, conn):
    """Sostituisce il connect di una connessione urllib3 con quello di
    `deadline.create_connection`: urllib3 non offre un punto per ricalcolare
    il timeout a ogni indirizzo. Mappa gli errori come `HTTPConnection._new_conn`
    (stessi messaggi finiti negli snapshot) e salta solo `sys.audit`."""
    from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

    def _new_conn():
        try:
            return deadline.create_connection(
                (conn._dns_host.strip("[]"), conn.port), conn.timeout,
                conn.source_address, conn.socket_options,
                guard=conn.proxy is None)  # con un proxy si connette al proxy, non al target
        except socket.gaierror as e:
            raise NameResolutionError(conn.host, conn, e) from e
        except socket.timeout as e:
            raise ConnectTimeoutError(
                conn, f"Connection to {conn.host} timed out. (connect timeout={conn.timeout})") from e
        except OSError as e:
            raise NewConnectionError(conn, f"Failed to establish a new connection: {e}") from e

    conn._new_conn = _new_conn
    return conn


def _tracked_get(deadline, url, **kwargs):
    """`requests.get` con i socket tracciati dal watchdog di `deadline` e il
    connect limitato dal residuo. L'hook è `get_connection_with_tls_context`
    perché restituisce il pool sia diretto sia via proxy da env."""
    adapter = req_lib.adapters.HTTPAdapter()
    get_pool = adapter.get_connection_with_tls_context

    def _tracking_pool(*args, **kw):
        pool = get_pool(*args, **kw)
        get_conn = pool._get_conn
        pool._get_conn = lambda *a, **k: _bound_connect(deadline, deadline.track(get_conn(*a, **k)))
        return pool

    adapter.get_connection_with_tls_context = _tracking_pool
    with req_lib.Session() as session:
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        resp = session.get(url, **kwargs)
    # Interrotto nella fase degli header, `http.client` legge l'EOF come fine
    # degli header e restituisce comunque una risposta (anche un 302 con
    # `Location` troncato): dopo la scadenza non si interpreta nulla.
    if deadline.expired():
        resp.close()
        raise TimeoutError(FETCH_DEADLINE_ERROR_PREFIX)
    return resp


def _tracked_urlopen(deadline, req, timeout, ctx):
    """`urlopen` con i socket tracciati dal watchdog di `deadline` e il connect
    limitato dal residuo."""
    def _conn(conn_cls, request, *a, **k):
        conn = deadline.track(conn_cls(*a, **k))
        # Con un proxy (anche per un target https, via tunnel) si connette al
        # proxy configurato dall'operatore: la guardia per IP non si applica.
        guard = not (request.has_proxy() or getattr(request, "_tunnel_host", None))
        # Punto di iniezione di http.client: sostituisce `socket.create_connection`.
        conn._create_connection = lambda *args: deadline.create_connection(*args, guard=guard)
        return conn

    def _tracking(handler):
        do_open = handler.do_open
        handler.do_open = lambda conn_cls, request, **kw: do_open(
            lambda *a, **k: _conn(conn_cls, request, *a, **k), request, **kw)
        return handler

    opener = urllib.request.build_opener(
        _tracking(urllib.request.HTTPHandler()),
        _tracking(urllib.request.HTTPSHandler(context=ctx)))
    return opener.open(req, timeout=timeout)


def http_get_with_retry(url, timeout=15, verify_ssl=False, max_attempts=3, base_delay=2,
                         max_bytes=None, max_seconds=None):
    # SEC-18: `max_seconds=None` usa MAX_FETCH_SECONDS, letta qui e non come
    # default-arg (monkeypatch/env a runtime). Un valore non valido
    # (0, negativo, nan, inf) ricade sulla costante con un warning, come l'env.
    # Il corpo vive in `_http_get_with_retry` perché ha molti `return`: il
    # `finally` qui garantisce che il thread del watchdog sia sempre fermato e atteso.
    limit = MAX_FETCH_SECONDS if max_seconds is None else _finite_positive_seconds(
        "max_seconds", max_seconds, MAX_FETCH_SECONDS)
    try:
        deadline = _FetchDeadline(limit)
    except RuntimeError as exc:
        # Senza watchdog il limite non c'è (header o body a goccia sarebbero
        # liberi): meglio non fare la richiesta. Il contratto dei chiamanti
        # (`/http`, crt.sh) è un dict con `error`, non un'eccezione.
        return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                "error": f"fetch watchdog unavailable: {exc}", "attempts": 0}
    try:
        return _http_get_with_retry(url, timeout, verify_ssl, max_attempts, base_delay,
                                    max_bytes, deadline)
    finally:
        deadline.close()


def _http_get_with_retry(url, timeout, verify_ssl, max_attempts, base_delay, max_bytes,
                         deadline):
    result = {"status_code": None, "content": None, "headers": {},
              "final_url": None, "error": None, "attempts": 0}
    ua = "Mozilla/5.0 (compatible; SOC-DomainIntelligence/4.0)"
    retryable = {429, 500, 502, 503, 504}
    # SEC-16: `max_bytes=None` (default) usa il cap generico corrente —
    # letto qui, non come default-arg, perché`MAX_FETCH_BODY_BYTES` deve
    # restare sovrascrivibile a runtime (env var o monkeypatch nei test).
    cap = MAX_FETCH_BODY_BYTES if max_bytes is None else max_bytes

    # SSRF guard: refuse to fetch a URL whose host resolves to an internal address.
    safe, reason = is_safe_url(url)
    if not safe:
        result["error"] = f"{SSRF_ERROR_PREFIX}: {reason}"
        return result

    cur = url  # URL dell'hop in corso: serve al gestore dell'errore, anche sul ramo `urllib`
    for attempt in range(1, max_attempts + 1):
        result["attempts"] = attempt
        result["error"] = None
        try:
            if HAS_REQUESTS:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                # Follow redirects manually so each hop is re-validated against SSRF
                # (a public site can 302 to http://169.254.169.254/ — allow_redirects
                # would follow it blindly).
                cur = url
                resp = None
                for _hop in range(5):
                    # SEC-16: `stream=True` — il body non viene scaricato qui,
                    # solo status/headers (letti per decidere il redirect).
                    resp = _tracked_get(deadline, cur, timeout=deadline.clamp(timeout),
                                        allow_redirects=False, headers={"User-Agent": ua},
                                        verify=verify_ssl, stream=True)
                    if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        nxt = _urljoin(cur, resp.headers["location"])
                        ok, why = is_safe_url(nxt)
                        if not ok:
                            resp.close()  # connessione mai drenata (stream=True): va chiusa esplicitamente
                            result["error"] = f"{SSRF_REDIRECT_ERROR_PREFIX}: {why}"
                            return result
                        resp.close()
                        cur = nxt
                        continue
                    break
                # SEC-16: streaming con stop non appena il body accumulato
                # raggiunge il cap — il byte oltre il cap non viene letto
                # dalla connessione (a differenza di un troncamento fatto
                # dopo aver scaricato tutto il body).
                _chunks = []
                _total = 0
                # SEC-16 (G6 round 2, rilievo ALTO): `resp.close()` in un
                # `finally` attorno al SOLO ciclo di streaming — se
                # `iter_content` solleva a metà (connessione rotta,
                # `IncompleteRead`/`ChunkedEncodingError`, o timeout di
                # lettura) il controllo salta comunque qui prima di
                # propagare all'`except` generico sotto, invece di saltare
                # `resp.close()` e perdere la connessione (leak). Sui rami di
                # successo/cap `close()` restava chiamato solo qui, non più
                # anche subito dopo il ciclo (nessuna doppia chiusura).
                try:
                    for _chunk in resp.iter_content(chunk_size=8192):
                        if not _chunk:
                            continue
                        _chunks.append(_chunk)
                        _total += len(_chunk)
                        if _total >= cap:
                            break
                finally:
                    resp.close()
                # SEC-18: il watchdog chiude il socket, ma un body senza
                # Content-Length termina con un EOF pulito, non con un'eccezione:
                # senza questo controllo il body troncato passerebbe per completo.
                if deadline.expired():
                    return _fetch_deadline_result(result, deadline)
                content = b"".join(_chunks)[:cap]
                result.update({"status_code": resp.status_code, "content": content,
                               "headers": dict(resp.headers),
                               "final_url": cur if cur != url else None})
                if resp.status_code in retryable and attempt < max_attempts:
                    deadline.sleep(base_delay * (2 ** (attempt - 1)))
                    continue
                return result
            else:
                req = urllib.request.Request(url, headers={"User-Agent": ua})
                ctx = ssl.create_default_context()
                if not verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with _tracked_urlopen(deadline, req, deadline.clamp(timeout), ctx) as resp:
                    final = resp.geturl()
                    if final != url:
                        ok, why = is_safe_url(final)
                        if not ok:
                            result["error"] = f"{SSRF_REDIRECT_ERROR_PREFIX}: {why}"
                            return result
                    # SEC-16: letto a blocchi fino al cap, non `resp.read()`
                    # intero — stesso limite del ramo `requests` sopra.
                    _chunks = []
                    _total = 0
                    while _total < cap:
                        _block = resp.read(min(8192, cap - _total))
                        if not _block:
                            break
                        _chunks.append(_block)
                        _total += len(_block)
                    result.update({"content": b"".join(_chunks), "status_code": resp.getcode(),
                                   "headers": dict(resp.headers),
                                   "final_url": final if final != url else None})
                # SEC-18: stesso controllo del ramo `requests` (EOF pulito).
                if deadline.expired():
                    return _fetch_deadline_result(result, deadline)
                return result
        except _SSRFConnectBlocked as e:
            # Terminale come la guardia per nome, nessun retry. Stesso prefisso
            # per hop di redirect e URL iniziale: `collection_failed` li legge
            # come un fatto sul dominio, non come un guasto del collector.
            prefix = SSRF_REDIRECT_ERROR_PREFIX if cur != url else SSRF_ERROR_PREFIX
            result["error"] = f"{prefix}: {e}"
            return result
        except Exception as e:
            # SEC-18: un'eccezione dopo la scadenza è l'effetto del watchdog (o
            # di `clamp`), non un errore del server: niente "Attempt n/m: ...".
            if deadline.expired():
                return _fetch_deadline_result(result, deadline)
            result["error"] = f"Attempt {attempt}/{max_attempts}: {e}"
            if attempt < max_attempts:
                deadline.sleep(base_delay * (2 ** (attempt - 1)))
    return result


# ═══════════════════════════════════════════════════════════════
# TLS
# ═══════════════════════════════════════════════════════════════

def inspect_tls(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    result = {"connected": False, "certificate": None, "error": None}
    deadline = None
    try:
        # Stessa funzione di connessione di `http_get_with_retry`: guardia
        # sull'IP effettivamente contattato e limite di durata complessivo
        # (MAX_FETCH_SECONDS) anche su host con più indirizzi. Se il thread del
        # watchdog non parte, `RuntimeError` finisce nell'`except` sotto: errore
        # nel dict e nessuna connessione, come in `http_get_with_retry`.
        deadline = _FetchDeadline(MAX_FETCH_SECONDS)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with deadline.create_connection((hostname, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    result["connected"] = True
                    result["certificate"] = {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                    }
                else:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        result["connected"] = True
                        result["certificate"] = {
                            "der_sha256": hashlib.sha256(der).hexdigest(),
                            "note": "binary cert only"
                        }
    except _SSRFConnectBlocked as e:
        result["error"] = f"{SSRF_ERROR_PREFIX}: {e}"
    except Exception as e:
        result["error"] = str(e)
    finally:
        if deadline is not None:
            deadline.close()
    return result


# ═══════════════════════════════════════════════════════════════
# HTML Processing
# ═══════════════════════════════════════════════════════════════

# SEC-47: una regex con un'apertura seguita da `.*?` o da un `[^>]*` non ancorato (`<script[^>]*>.*?</script>`,
# `<!--.*?-->`, `<[^>]+>`, `<input[^>]*type=...`), su un corpo con molte aperture senza chiusura, rilegge il corpo
# fino alla fine da ogni apertura: costo quadratico, cubico con due `[^>]*`. `re` tiene il GIL per tutta la
# chiamata, quindi resta fermo l'intero processo, e il corpo lo sceglie chi controlla il dominio analizzato.
# Le scansioni qui sotto danno gli stessi risultati delle regex che sostituiscono (scritte in ogni docstring)
# passando sul corpo una volta sola: se da un'apertura la chiusura non c'è, non c'è nemmeno per le aperture
# successive; e le aperture `<tag` che hanno lo stesso primo `>` dopo di sé hanno lo stesso esito.
# Le parole si cercano con `re` e IGNORECASE come nelle regex originali, non con `str.find` sul testo in
# minuscolo: `re` fa coincidere anche `ſ` con `s` e `İ` con `i`, e `lower()` cambia la lunghezza di `İ`.
_SCRIPT_OPEN = re.compile(r'<script', re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r'</script>', re.IGNORECASE)
_STYLE_OPEN = re.compile(r'<style', re.IGNORECASE)
_STYLE_CLOSE = re.compile(r'</style>', re.IGNORECASE)
_TITLE_OPEN = re.compile(r'<title', re.IGNORECASE)
_TITLE_CLOSE = re.compile(r'</title>', re.IGNORECASE)
_META_OPEN = re.compile(r'<meta', re.IGNORECASE)
_META_EQUIV_REFRESH = re.compile(r'http-equiv\s*=\s*["\']?refresh', re.IGNORECASE)
_CONTENT_WORD = re.compile(r'content', re.IGNORECASE)
_META_CONTENT = re.compile(r'content\s*=\s*["\']?([^"\'> ]+)', re.IGNORECASE)
_DIV_OPEN = re.compile(r'<div', re.IGNORECASE)
_DIV_CLOSE = re.compile(r'</div>', re.IGNORECASE)
_STYLE_ATTR = re.compile(r'style\s*=\s*["\']', re.IGNORECASE)
_CLASS_ATTR = re.compile(r'class\s*=\s*["\']', re.IGNORECASE)
_QUOTE = re.compile(r'["\']')
_DISPLAY_NONE = re.compile(r'display\s*:\s*none', re.IGNORECASE)
_VISIBILITY_HIDDEN = re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE)
_HIDDEN_WORD = re.compile(r'hidden', re.IGNORECASE)
_BASE64_PREFIX = re.compile(r'atob\s*\(\s*["\']|data:')
_BASE64_BODY = re.compile(r'[A-Za-z0-9+/=]{100,}')


def _tag_blocks(html, open_re, close_re):
    """(inizio, inizio del contenuto, fine del contenuto, fine) di ogni `<tag[^>]*>(.*?)</tag>` (IGNORECASE,
    DOTALL), nell'ordine e con le posizioni di `re.finditer`."""
    pos = 0
    while True:
        tag = open_re.search(html, pos)
        if tag is None:
            return
        gt = html.find('>', tag.end())
        if gt < 0:
            return
        close = close_re.search(html, gt + 1)
        if close is None:
            return
        yield tag.start(), gt + 1, close.start(), close.end()
        pos = close.end()


def _comment_blocks(html):
    """(inizio, fine) di ogni `<!--.*?-->` (DOTALL), nell'ordine di `re.finditer`."""
    pos = 0
    while True:
        start = html.find('<!--', pos)
        if start < 0:
            return
        close = html.find('-->', start + 4)
        if close < 0:
            return
        yield start, close + 3
        pos = close + 3


def _without_spans(html, spans):
    """`html` senza i tratti (inizio, fine), dati in ordine e disgiunti."""
    parts, last = [], 0
    for start, end in spans:
        parts.append(html[last:start])
        last = end
    parts.append(html[last:])
    return "".join(parts)


def _without_tag_blocks(html, open_re, close_re):
    """`re.sub(r'<tag[^>]*>.*?</tag>', '', html, flags=re.DOTALL | re.IGNORECASE)`."""
    return _without_spans(html, ((start, end) for start, _, _, end in _tag_blocks(html, open_re, close_re)))


def _replace_tags(html, repl):
    """`re.sub(r'<[^>]+>', repl, html)`."""
    parts, last, pos = [], 0, 0
    while True:
        start = html.find('<', pos)
        if start < 0:
            break
        gt = html.find('>', start + 1)
        if gt < 0:
            break
        if gt > start + 1:  # `<>` non è un tag: `[^>]+` vuole almeno un carattere
            parts.append(html[last:start])
            parts.append(repl)
            last = gt + 1
        pos = gt + 1
    parts.append(html[last:])
    return "".join(parts)


def _findall_tag_token(html, tag_re, token_re):
    """`re.findall('<tag[^>]*TOKEN', html, re.IGNORECASE)` per i pattern di `_TAG_TOKEN_SCANS`: il `[^>]*` goloso
    arriva all'ultimo TOKEN prima del primo `>` dopo il tag (o della fine del corpo). Vale perché TOKEN non contiene
    `>`, non ha gruppi e due sue occorrenze non si sovrappongono."""
    found, pos = [], 0
    while True:
        tag = tag_re.search(html, pos)
        if tag is None:
            return found
        gt = html.find('>', tag.end())
        if gt < 0:
            gt = len(html)
        last = None
        for token in token_re.finditer(html, tag.end(), gt):
            last = token
        if last is None:
            pos = gt
        else:
            found.append(html[tag.start():last.end()])
            pos = last.end()


# I pattern `<tag[^>]*TOKEN` di DEFAULT_SUSPICIOUS_PATTERNS, con le parti della loro scansione lineare. La chiave
# è il pattern sostituito: se quello di `shared/constants.py` cambia, si torna a `re.findall`.
_TAG_TOKEN_SCANS = {
    tag + "[^>]*" + token: (re.compile(tag, re.IGNORECASE), re.compile(token, re.IGNORECASE))
    for tag, token in (("<form", r"action"),
                       ("<input", r"type=[\\\"']?password"),
                       ("<input", r"type=[\\\"']?email"))
}


def _meta_refresh_contents(html):
    r"""Il gruppo di ogni `<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?([^"\'> ]+)`
    (IGNORECASE), nell'ordine di `re.finditer`."""
    contents, pos = [], 0
    while True:
        tag = _META_OPEN.search(html, pos)
        if tag is None:
            return contents
        gt = html.find('>', tag.end())
        if gt < 0:
            gt = len(html)
        equiv = _META_EQUIV_REFRESH.search(html, tag.end(), gt)
        if equiv is not None:
            # Il `[^>]*` goloso davanti a `content` prende l'ultimo `content=` del tag che dà un valore; lo si cerca
            # dopo il primo `http-equiv=refresh`, che lascia la scelta più ampia.
            starts = [word.start() for word in _CONTENT_WORD.finditer(html, equiv.end(), gt)]
            for start in reversed(starts):
                content = _META_CONTENT.match(html, start, gt)
                if content:
                    contents.append(content.group(1))
                    break
        pos = gt + 1


def _hidden_div_blocks(html, attr_re, value_re, closers):
    r"""(inizio, inizio del contenuto, fine del contenuto, fine) di ogni
    `<div[^>]*ATTR\s*=\s*["\'][^"\']*VALUE[^"\']*["\'][^>]*>(.*?)</div>` (IGNORECASE, DOTALL), nell'ordine di
    `re.finditer`. `closers` sono le posizioni di ogni `</div>`, in ordine."""
    pos = 0
    while True:
        tag = _DIV_OPEN.search(html, pos)
        if tag is None:
            return
        gt = html.find('>', tag.end())
        if gt < 0:
            return
        block = None
        # Il `[^>]*` goloso prova prima l'ultimo attributo del tag.
        for attr in reversed(list(attr_re.finditer(html, tag.end(), gt))):
            quote = _QUOTE.search(html, attr.end())
            if quote is None or not value_re.search(html, attr.end(), quote.start()):
                continue
            # Il valore fra apici può scavalcare il primo `>`: allora il tag finisce al primo `>` dopo l'apice. Può
            # farlo solo l'ultimo attributo del tag; per gli altri il `>` è `gt`, senza cercarlo di nuovo: su un tag
            # con migliaia di attributi la ricerca ripetuta da ciascuno tornerebbe quadratica.
            open_end = gt if quote.start() < gt else html.find('>', quote.end())
            if open_end < 0:
                continue
            i = bisect.bisect_left(closers, open_end + 1)
            if i < len(closers):
                block = (tag.start(), open_end + 1, closers[i], closers[i] + len('</div>'))
                break
        if block is None:
            pos = gt
        else:
            yield block
            pos = block[3]


def _base64_blocks(html):
    r"""(inizio, gruppo) di ogni `(?:atob\s*\(\s*["\']|data:[^;]+;base64,)([A-Za-z0-9+/=]{100,})`, nell'ordine di
    `re.finditer`."""
    pos, semicolon = 0, -1
    while True:
        prefix = _BASE64_PREFIX.search(html, pos)
        if prefix is None:
            return
        start, body = prefix.start(), prefix.end()
        if html.startswith('data:', start):
            # `[^;]+` arriva al primo `;` e vuole almeno un carattere. Quel `;` vale per ogni `data:` che lo precede:
            # si cerca di nuovo solo quando resta indietro.
            if semicolon < start + 5:
                semicolon = html.find(';', start + 5)
                if semicolon < 0:
                    semicolon = len(html)
            if semicolon == start + 5 or not html.startswith(';base64,', semicolon):
                pos = start + 1
                continue
            body = semicolon + len(';base64,')
        b64 = _BASE64_BODY.match(html, body)
        if b64 is None:
            pos = start + 1
            continue
        yield start, b64.group()
        pos = b64.end()


def extract_title(html: str) -> str | None:
    """Contenuto del primo `<title[^>]*>(.*?)</title>` (IGNORECASE, DOTALL), o None."""
    block = next(_tag_blocks(html, _TITLE_OPEN, _TITLE_CLOSE), None)
    return html[block[1]:block[2]] if block else None


def normalize_html_for_fingerprint(html: str) -> str:
    """Normalizza HTML rimuovendo rumore dinamico per fingerprinting stabile."""
    text = _without_tag_blocks(html, _SCRIPT_OPEN, _SCRIPT_CLOSE)
    text = _without_tag_blocks(text, _STYLE_OPEN, _STYLE_CLOSE)
    text = _without_spans(text, _comment_blocks(text))
    text = re.sub(r'\b\d{10,13}\b', '', text)  # timestamps
    text = re.sub(r'[0-9a-f]{32,64}', '', text, flags=re.IGNORECASE)  # hashes/tokens
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_visible_text(html: str) -> str:
    """Estrae testo visibile da HTML."""
    text = _without_tag_blocks(html, _SCRIPT_OPEN, _SCRIPT_CLOSE)
    text = _without_tag_blocks(text, _STYLE_OPEN, _STYLE_CLOSE)
    text = _replace_tags(text, ' ')
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def detect_suspicious_patterns(html: str, patterns: list[str]) -> list[dict]:
    """Cerca pattern sospetti in HTML."""
    findings = []
    for pattern in patterns:
        try:
            scan = _TAG_TOKEN_SCANS.get(pattern)
            matches = _findall_tag_token(html, *scan) if scan else re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern": pattern,
                    "count": len(matches),
                    "samples": matches[:3]
                })
        except re.error:
            pass
    return findings


def _strip_www(host: str) -> str:
    """Normalizza un hostname per il confronto: minuscole, senza prefisso "www."
    e senza porta.

    NON usare `lstrip("www.")`: `str.lstrip` toglie qualunque carattere iniziale
    appartenente all'insieme {w, .}, non il prefisso. Su "wind.it" restituirebbe
    "ind.it" e su "wallmart.com" "allmart.com", falsando il confronto fra il
    dominio del sito e gli host delle sue risorse.

    La porta va rimossa perché l'host di una risorsa è estratto dall'URL nell'HTML
    e può quindi contenerla ("static.wind.it:8443"), mentre il dominio del sito non
    l'ha mai: senza normalizzazione una risorsa self-hosted su porta non standard
    risulterebbe di terze parti.
    """
    host = re.sub(r"^www\.", "", (host or "").lower())
    return host.split(":", 1)[0]


class _TagCollector(HTMLParser):
    """CLS-01g (3° giro): tokenizer HTML reale al posto di una grammatica
    regex per-attributo scritta a mano. Raccoglie ogni occorrenza dei tag
    richiesti con gli attributi già strutturati — quotati, non quotati o
    malformati ('=' orfano, apici nel valore: lo stdlib li interpreta come
    un browser, non come regex a boundary fisse — e il testo sorgente esatto
    del tag di apertura (via `get_starttag_text()`). Parametrizzata sui nomi
    di tag, non specifica dell'iframe: `CLS-01h` (form nascosti) e `CLS-01i`
    (estrazione width/height/style) sono entrambi realizzati sullo stesso parser.
    """

    def __init__(self, tag_names):
        super().__init__(convert_charrefs=True)
        self._targets = {t.lower() for t in tag_names}
        self.tags = []  # [{"name", "attrs", "text", "self_closing", "_opaque"}, ...]
        # CLS-01j/CLS-01q/CLS-01v (G6 round 3): gli elementi RAWTEXT reali NON
        # hanno nesting — il contenuto di un <iframe> finisce alla PRIMA
        # occorrenza letterale di `</iframe`, punto. Non esiste un secondo
        # iframe "annidato" dal punto di vista del parser reale: quel markup
        # è testo inerte dentro il primo. Un solo indice (non una pila): al
        # più UNA regione opaca è attiva alla volta. `None` = nessuna
        # regione attiva. Un <iframe> che compare testualmente MENTRE una
        # regione è già attiva non ne apre una seconda (non c'è nesting da
        # tracciare) — resta comunque raccolto in `self.tags` e verrà
        # marcato opaco insieme al resto SOLO SE/QUANDO la regione attiva si
        # chiude regolarmente. Se non si chiude mai (EOF), niente viene
        # marcato: stato reale richiesto da CLS-01q, non un'euristica sulla
        # forma del markup. Ogni tag viene marcato opaco al più UNA volta in
        # tutto il parsing (bloccante 2/CLS-01v: elimina l'O(k) per chiusura
        # della pila, che su nesting ben chiuso costava O(n²)).
        self._opaque_start = None

    def _collect(self, tag, attrs, self_closing):
        if tag in self._targets:  # HTMLParser passa già `tag` in minuscolo
            # CLS-01g (4° giro): `setdefault` invece di una dict comprehension
            # — su un attributo ripetuto (es. `width="0" width="400"`) la spec
            # HTML5/i browser tengono il PRIMO valore, la comprehension teneva
            # l'ultimo. Valori già decodificati dalle entity HTML da `html.parser`
            # (`unescape` interno): chi li visualizza altrove deve fare escape,
            # sono potenziale stored-XSS se re-iniettati così come sono.
            attr_dict = {}
            for name, value in attrs:
                attr_dict.setdefault(name.lower(), value)
            self.tags.append({
                "name": tag,
                "attrs": attr_dict,
                "text": self.get_starttag_text() or f"<{tag}>",
                "self_closing": self_closing,
                # CLS-01j/CLS-01q: marcato True da `handle_endtag` se questo
                # tag viene raccolto all'interno di un container (iframe)
                # che poi si chiude regolarmente — le categorie vive di
                # `detect_hidden_elements` lo scartano.
                "_opaque": False,
            })

    def handle_starttag(self, tag, attrs):
        self._collect(tag, attrs, self_closing=False)
        if tag in self._SUPPRESS_RAWTEXT and self._opaque_start is None:
            # Apre una regione opaca SOLO SE nessuna è già attiva: un
            # <iframe> incontrato mentre siamo già dentro il raw content di
            # un altro non è un secondo container reale (niente nesting in
            # RAWTEXT), è testo che diventerà opaco insieme al resto se/quando
            # la regione attiva si risolve.
            self._opaque_start = len(self.tags)

    def handle_startendtag(self, tag, attrs):
        # Self-closing: nessun contenuto nested, nessuna apertura di regione.
        self._collect(tag, attrs, self_closing=True)

    def handle_endtag(self, tag):
        # CLS-01j/CLS-01q/CLS-01v: la PRIMA occorrenza letterale di
        # `</iframe` chiude la regione opaca attiva (se ce n'è una) — tutto
        # ciò che vi è stato raccolto nel frattempo è fallback content opaco
        # per spec WHATWG (mai renderizzato/tokenizzato da un browser), va
        # escluso. Ogni `</iframe>` ulteriore, senza una regione attiva da
        # chiudere, è un end-tag orfano (nessun elemento realmente aperto in
        # un browser reale) e viene ignorato. Se la regione non si chiude
        # mai (EOF), resta `_opaque_start` non-None e niente viene marcato:
        # e' lo stato reale richiesto da CLS-01q, non un'euristica sulla
        # forma del markup. Essendo al più una regione attiva alla volta,
        # le regioni marcate non si sovrappongono mai: ogni tag di
        # `self.tags` viene toccato da questo ciclo al più una volta in
        # tutto il parsing (non ad ogni chiusura annidata come con la pila
        # LIFO), quindi il lavoro totale sul documento resta O(n): elimina
        # l'O(n²) di CLS-01v.
        if tag in self._SUPPRESS_RAWTEXT and self._opaque_start is not None:
            for t in self.tags[self._opaque_start:]:
                t["_opaque"] = True
            self._opaque_start = None

    # CLS-01j/CLS-01q: `HTMLParser.CDATA_CONTENT_ELEMENTS` include "iframe" —
    # senza questo override un <iframe> (chiuso o no) fa entrare il parser
    # in modalità RAWTEXT e i tag annidati non arrivano mai a
    # `handle_starttag`/`handle_endtag`, rendendo impossibile lo stato reale
    # sopra. Sopprimendola sempre, i tag interni tornano tokenizzati
    # normalmente; l'opacità del fallback content di un iframe regolarmente
    # chiuso è ora responsabilità di `handle_endtag`, non di questo metodo.
    # Solo "iframe" oggi: `script`/`style` restano in RAWTEXT, perché il
    # loro contenuto (JS/CSS con `<`/`>` legittimi, es. `if (a<b)`) verrebbe
    # altrimenti interpretato come markup.
    _SUPPRESS_RAWTEXT = frozenset({"iframe"})

    def set_cdata_mode(self, elem, **kwargs):
        # SEC-51: fino a CPython 3.12.11 la libreria chiama `set_cdata_mode(elem)` e il metodo base non accetta
        # `escapable`: passarlo sempre faceva fallire ogni pagina con `<script>` o `<style>`. Si inoltra solo ciò che
        # la libreria passa.
        if elem.lower() in self._SUPPRESS_RAWTEXT:
            return
        super().set_cdata_mode(elem, **kwargs)

    def reset(self):
        super().reset()
        # SEC-51: le versioni che hanno `_support_cdata` lo accendono a ogni `reset`, e allora `<![CDATA[` apre una
        # sezione fino a `]]>` che nasconde i tag al suo interno. Nel contenuto HTML il browser la legge come commento
        # fino al primo `>`: spenta, la libreria fa lo stesso.
        if hasattr(self, "_set_support_cdata"):
            self._set_support_cdata(False)

    def parse_marked_section(self, i, report=1):
        # SEC-51: fino a CPython 3.12.11 ogni `<![` arriva qui, e `_markupbase` solleva `AssertionError` su una parola
        # chiave sconosciuta (`<![foo[x]]>`): l'analisi della pagina falliva. Le versioni successive, con
        # `_support_cdata` spento (sopra), lo leggono come commento fino al primo `>`, come il browser nel contenuto
        # HTML: qui la stessa grammatica.
        end = self.rawdata.find(">", i + 3)
        return -1 if end < 0 else end + 1


# SEC-48: tre regex della libreria standard (`locatetagend`, `tagfind_tolerant`, `attrfind_tolerant`) ripetono un
# gruppo composto, che `sre` esegue in una sola chiamata C con un frame sul proprio stack per ogni ripetizione: un
# tag con molti attributi o molti spazi, chiuso o no, tiene il GIL per tutta la sua lunghezza e ferma dashboard,
# login e sonde dello stesso processo. `_TagCollector` esegue il codice dei tre metodi che le usano, quello
# dell'interprete (la decodifica dei valori in `parse_starttag` cambia fra le versioni di Python), con al posto delle
# regex grammatiche equivalenti a costo limitato per chiamata. Valgono solo per il testo esatto qui sotto, copiato
# dalla libreria standard: se gli interni sono diversi resta il parser standard, lento ma con gli stessi risultati.
# Le tre regex vengono da `Lib/html/parser.py` di CPython, Copyright (c) Python Software Foundation, sotto la
# Python Software Foundation License (PSF-2.0).
_STDLIB_TAGFIND = r'([a-zA-Z][^\t\n\r\f />]*)(?:[\t\n\r\f ]|/(?!>))*'
_STDLIB_ATTRFIND = r"""
  (
    (?<=['"\t\n\r\f /])[^\t\n\r\f />][^\t\n\r\f /=>]*  # attribute name
   )
  ([\t\n\r\f ]*=[\t\n\r\f ]*        # value indicator
    ('[^']*'                        # LITA-enclosed value
    |"[^"]*"                        # LIT-enclosed value
    |(?!['"])[^>\t\n\r\f ]*         # bare value
    )
   )?
  (?:[\t\n\r\f ]|/(?!>))*           # possibly followed by a space
"""
_STDLIB_LOCATETAGEND = r"""
  [a-zA-Z][^\t\n\r\f />]*           # tag name
  [\t\n\r\f /]*                     # optional whitespace before attribute name
  (?:(?<=['"\t\n\r\f /])[^\t\n\r\f />][^\t\n\r\f /=>]*  # attribute name
    (?:[\t\n\r\f ]*=[\t\n\r\f ]*    # value indicator
      (?:'[^']*'                    # LITA-enclosed value
        |"[^"]*"                    # LIT-enclosed value
        |(?!['"])[^>\t\n\r\f ]*     # bare value
       )
     )?
    [\t\n\r\f /]*                   # possibly followed by a space
   )*
   >?
"""
_STDLIB_TAG_REGEXES = {"tagfind_tolerant": (_STDLIB_TAGFIND, 0), "attrfind_tolerant": (_STDLIB_ATTRFIND, re.VERBOSE),
                       "locatetagend": (_STDLIB_LOCATETAGEND, re.VERBOSE)}

# Coda di `tagfind_tolerant` e `attrfind_tolerant`: spazi e `/`, ma non un `/` seguito da `>`. In una sequenza di spazi
# e `/` solo l'ultimo carattere può precedere `>`, quindi la coda è la sequenza intera letta con una classe di
# caratteri (un ciclo in C, senza frame per carattere), meno quel `/` finale. Chiude il pattern e può restare vuota:
# non fa mai tornare indietro le parti precedenti, che danno gli stessi gruppi.
_TOLERANT_TAIL = r"(?:[\t\n\r\f ]|/(?!>))*"
_BOUNDED_TAIL = r"(?:[\t\n\r\f /]*(?:[\t\n\r\f ]|/(?!>)))?"
_BOUNDED_TAGFIND = re.compile(_STDLIB_TAGFIND.replace(_TOLERANT_TAIL, _BOUNDED_TAIL))
_BOUNDED_ATTRFIND = re.compile(_STDLIB_ATTRFIND.replace(_TOLERANT_TAIL, _BOUNDED_TAIL), re.VERBOSE)

# `locatetagend` a blocchi di al più 256 attributi per chiamata C, col ciclo fra un blocco e l'altro in Python, dove il
# GIL passa. Ogni blocco riprende dall'ultimo attributo letto (il lookbehind vede il carattere prima della posizione di
# partenza) e si ferma dove si fermerebbe la ripetizione intera; il `>` catturato dice che il tag è finito, quindi un
# tag normale costa una chiamata.
_LOCATE_ATTRS = r"""(?:(?<=['"\t\n\r\f /])[^\t\n\r\f />][^\t\n\r\f /=>]*
    (?:[\t\n\r\f ]*=[\t\n\r\f ]*(?:'[^']*'|"[^"]*"|(?!['"])[^>\t\n\r\f ]*))?
    [\t\n\r\f /]*){0,256}(>)?"""
_LOCATE_FIRST_BLOCK = re.compile(r"[a-zA-Z][^\t\n\r\f />]*[\t\n\r\f /]*" + _LOCATE_ATTRS, re.VERBOSE)
_LOCATE_NEXT_BLOCK = re.compile(_LOCATE_ATTRS, re.VERBOSE)


class _LocateTagEndInBlocks:
    """Al posto di `locatetagend`: `match` dà un match con la stessa fine, l'unica cosa che i metodi ne leggono."""

    @staticmethod
    def match(rawdata, pos):
        m = _LOCATE_FIRST_BLOCK.match(rawdata, pos)
        while m is not None and m.group(1) is None:
            following = _LOCATE_NEXT_BLOCK.match(rawdata, m.end())
            if following.end() == m.end():
                break
            m = following
        return m


# I metodi della libreria standard che leggono le tre regex, coi nomi che devono usare.
_BOUNDED_PARSER_METHODS = {"check_for_whole_start_tag": {"locatetagend"},
                           "parse_starttag": {"tagfind_tolerant", "attrfind_tolerant"},
                           "parse_endtag": {"locatetagend", "tagfind_tolerant"}}
# Prova all'import: guidato come in `detect_hidden_elements` (buffer assegnato, poi `close`), il parser a costo
# limitato deve dare i tag di `feed` + `close` del parser standard. Copre gli interni che il controllo sul testo delle
# regex non vede (il buffer `rawdata`, `close`) e passa il confine fra due blocchi.
_BOUNDED_PARSER_PROBES = (
    '<form style="display:none" action=/f><input type=hidden name=a value=b></form>'
    '<img src="/p?a=1&amp;b=2&copy=3" width=1 height=1><img\fsrc=///\fwidth=1 height=1/>'
    "<iframe src=//f.example/ width=0 height=0><img src=//d.example/q.gif></iframe b=c >"
    "<a b c=d e='>' g / / >x</a / ><img src = x / width=1 height=1/><iframe src=y",
    "<img" + " b=c" * 300 + " src=//m.example/ width=1 height=1></a" + " b" * 300 + "><form <form action=y",
)


def _install_bounded_parser():
    """Mette in `_TagCollector` i tre metodi col loro codice e i loro globali, salvo le tre regex. None se gli interni
    sono quelli attesi, altrimenti il motivo per cui resta il parser standard."""
    methods = {}
    for name, regexes in _BOUNDED_PARSER_METHODS.items():
        stock = vars(HTMLParser).get(name)
        if not isinstance(stock, types.FunctionType) or not regexes <= set(stock.__code__.co_names):
            return f"HTMLParser.{name} assente o senza le regex attese"
        for regex in regexes:
            if stock.__globals__.get(regex) != re.compile(*_STDLIB_TAG_REGEXES[regex]):
                return f"html.parser.{regex} assente o con un'altra grammatica"
        namespace = {**stock.__globals__, "locatetagend": _LocateTagEndInBlocks,
                     "tagfind_tolerant": _BOUNDED_TAGFIND, "attrfind_tolerant": _BOUNDED_ATTRFIND}
        methods[name] = types.FunctionType(stock.__code__, namespace, name, stock.__defaults__, stock.__closure__)
        methods[name].__kwdefaults__ = stock.__kwdefaults__
    bounded = type("_BoundedTagCollector", (_TagCollector,), methods)
    tag_names = ("iframe", "form", "img")
    try:
        for page in _BOUNDED_PARSER_PROBES:
            expected = _TagCollector(tag_names)
            expected.feed(page)
            expected.close()
            candidate = bounded(tag_names)
            candidate.rawdata = page
            candidate.close()
            if candidate.tags != expected.tags:
                return "prova all'import diversa dal parser standard"
    except Exception as exc:  # un interno cambiato può sollevare qualunque cosa: resta il parser standard
        return f"prova all'import fallita ({type(exc).__name__})"
    for name, method in methods.items():
        setattr(_TagCollector, name, method)
    return None


# None se `_TagCollector` usa le regex a costo limitato, altrimenti il motivo per cui resta il parser standard.
_HTML_PARSER_FALLBACK = _install_bounded_parser()
if _HTML_PARSER_FALLBACK is not None:
    logger.warning("SEC-48: parser HTML standard, lento sui tag con molti attributi: %s", _HTML_PARSER_FALLBACK)


# SEC-50: la libreria standard decodifica un riferimento decimale (`&#` e cifre) con `int()` sulle cifre, che oltre
# `sys.get_int_max_str_digits()` cifre, zeri iniziali compresi, solleva e interrompe l'analisi della pagina, e senza
# quel limite costa un tempo più che lineare nelle cifre. Il browser legge tutte le cifre: gli zeri iniziali non
# contano e un valore oltre U+10FFFF dà U+FFFD. Nel testo e nei valori di attributo di `_TagCollector` un riferimento
# decimale di 8 cifre o più arriva alla decodifica ridotto a 7 cifre al più, quante ne servono fino a U+10FFFF
# (1114111): senza gli zeri iniziali (0 se sono tutte zeri), oppure 1114112, il primo valore fuori dall'intervallo,
# se ne restano più di 7. Il risultato è quello della libreria standard senza limite, che decodifica come il browser
# gli zeri iniziali e i valori oltre U+10FFFF (alcuni controlli, come U+0001, e i non-caratteri restano tolti, come a
# qualunque lunghezza); cambia solo la stringa da decodificare, non il buffer né il testo sorgente dei tag. Installata
# a parte dal parser a costo limitato, la riduzione vale anche col parser standard del ripiego. Se un metodo non legge
# come nome globale `unescape` o `_unescape_attrvalue`, o questi non passano da `html.unescape`, restano i metodi
# standard, con un avviso: un import che solleva fermerebbe i servizi che importano questo modulo, in modalità
# unified tutti, e una riduzione che non agisce non lascerebbe traccia. Il controllo guarda solo i nomi letti: un
# cambiamento che sposti uno solo dei punti di decodifica non lo vede, e lo segnalano i test su quell'interprete.
_LONG_DECIMAL_CHARREF = re.compile(r"&#([0-9]{8,})")


def _reduced_decimal_charref(match):
    digits = match.group(1).lstrip("0") or "0"
    return "&#" + (digits if len(digits) <= 7 else "1114112")


def _reduce_decimal_charrefs(text):
    return _LONG_DECIMAL_CHARREF.sub(_reduced_decimal_charref, text) if "&#" in text else text


def _install_bounded_charrefs():
    """Mette in `_TagCollector` `goahead` (testo) e `parse_starttag` (valori di attributo) col loro codice e i loro
    globali, salvo le funzioni di decodifica, che ricevono i riferimenti decimali già ridotti. None se i due metodi
    leggono la decodifica coi nomi globali attesi e questa passa da `html.unescape`, altrimenti il motivo per cui
    restano i metodi standard: il controllo è sui nomi letti, non su ogni punto in cui un metodo decodifica."""
    import dis
    from html import unescape

    def bounded_unescape(text):
        return unescape(_reduce_decimal_charrefs(text))

    methods = {}
    try:
        for name, decoders in (("goahead", {"unescape"}), ("parse_starttag", {"unescape", "_unescape_attrvalue"})):
            method = getattr(_TagCollector, name, None)   # se c'è, il `parse_starttag` delle regex a costo limitato
            if not isinstance(method, types.FunctionType):
                return f"HTMLParser.{name} assente o non è una funzione"
            # letti come nomi globali: in `html.unescape(...)` il nome letto è `html`, che la sostituzione non tocca
            loaded = decoders & {op.argval for op in dis.get_instructions(method) if op.opname == "LOAD_GLOBAL"}
            if not loaded:
                return f"HTMLParser.{name} non legge {' né '.join(sorted(decoders))} come nome globale"
            # la riduzione dà gli stessi caratteri solo con la decodifica di `html.unescape`
            if method.__globals__.get("unescape") is not unescape:
                return f"l'`unescape` di HTMLParser.{name} non è html.unescape"
            decode = method.__globals__.get("_unescape_attrvalue")   # dove gli attributi si decodificano a parte
            decoded_by = getattr(decode, "__globals__", {}).get("unescape")
            if (decode is not None or "_unescape_attrvalue" in loaded) and decoded_by is not unescape:
                return "html.parser._unescape_attrvalue non decodifica con html.unescape"
            namespace = {**method.__globals__, "unescape": bounded_unescape}
            if decode is not None:
                namespace["_unescape_attrvalue"] = lambda text, decode=decode: decode(_reduce_decimal_charrefs(text))
            methods[name] = types.FunctionType(method.__code__, namespace, name, method.__defaults__,
                                               method.__closure__)
            methods[name].__kwdefaults__ = method.__kwdefaults__
    except Exception as exc:  # un interno cambiato può sollevare qualunque cosa: restano i metodi standard
        return f"controllo degli interni della decodifica fallito ({type(exc).__name__})"
    for name, method in methods.items():   # tutti o nessuno: mai un metodo ridotto accanto a uno standard
        setattr(_TagCollector, name, method)
    return None


# None se `_TagCollector` riduce i riferimenti decimali lunghi, altrimenti il motivo per cui non lo fa.
_CHARREF_FALLBACK = _install_bounded_charrefs()
if _CHARREF_FALLBACK is not None:
    logger.warning("SEC-50: riferimenti decimali lunghi non ridotti, l'analisi di una pagina con uno oltre il limite "
                   "di cifre di int() fallisce: %s", _CHARREF_FALLBACK)


# ── CLS-01z: markup iframe/form/img morto (mai renderizzato per costruzione)
# verso un host esterno. Decisione utente (BUG-REGISTER.md §6, round-3):
# scope ristretto al SOLO caso (a) "fallback_content" — i casi (b)
# "malformed_endtag_swallow" e (c) "bogus_comment" sono stati rimossi:
# portavano un doppio conteggio reale (un end-tag con attributi bogus
# chiude comunque l'elemento per un browser — non crea markup morto, la
# premessa del caso (b) era empiricamente falsa) e un DoS per-span (~4,3s
# su 2 MB avversariale, un `_TagCollector` fresco istanziato per ogni span
# inghiottito/bogus). Nessuna modifica a `_TagCollector`/`set_cdata_mode`/
# `_opaque_start`/`handle_starttag`/`handle_endtag` — bit-identici, i 43
# test iframe esistenti li chiamano invariati.
#
# Caso (a) "fallback_content": il markup è già raccolto e marcato
# `_opaque=True` da `_TagCollector` quando un container RAWTEXT (`iframe`)
# si chiude regolarmente — le categorie vive lo scartano, qui va solo
# recuperato, non ri-derivato con una nuova grammatica.

# Tag valutati per il markup morto: gli stessi tre già coperti dalle
# categorie sorelle vive (hidden_forms/invisible_iframes/tracking_pixels).
_DEAD_MARKUP_TAGS = ("iframe", "form", "img")

# CLS-01z round-2 (falso positivo CDN): whitelist usata da `external_resources`
# (sezione 8 di `detect_hidden_elements`), con lo stesso confronto largo
# `safe in url` di sempre — comportamento INVARIATO, `CLS-01ab` la traccia.
_CDN_WHITELIST = (
    'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jquery.com',
    'bootstrapcdn.com', 'cdnjs.com', 'jsdelivr.net', 'unpkg.com',
    'google-analytics.com', 'googletagmanager.com', 'facebook.com',
    'twitter.com', 'schema.org', 'w3.org',
    'wp.com', 'wordpress.org', 'gravatar.com', 'fonts.', 'fontawesome',
    'youtube.com', 'vimeo.com', 'linkedin.com', 'instagram.com'
)

# CLS-01z round-4 (FN frammenti, decisione utente): `_dead_markup_external_host`
# usava `_CDN_WHITELIST` sopra, che contiene due voci FRAMMENTO non ancorate
# ('fonts.', 'fontawesome') — un host attaccante con SLD letteralmente
# 'fontawesome' su un TLD arbitrario (`fontawesome.xyz`) o primo label
# 'fonts' su un dominio arbitrario (`fonts.evil.example`) le matchava
# comunque, evadendo il detector (PoC verifier round-3). Whitelist SEPARATA,
# solo host CDN PIENI (eTLD+1 esatti), matching per suffisso di dominio
# soltanto — nessun frammento, nessuno `startswith`/label-nudo. `fonts.
# googleapis.com`/`fonts.gstatic.com` restano coperti di riflesso dalle
# voci a dominio pieno `googleapis.com`/`gstatic.com` (suffisso), quindi non
# ripetuti qui.
_DEAD_MARKUP_CDN_WHITELIST = (
    'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jquery.com',
    'bootstrapcdn.com', 'cdnjs.com', 'jsdelivr.net', 'unpkg.com',
    'google-analytics.com', 'googletagmanager.com', 'facebook.com',
    'twitter.com', 'schema.org', 'w3.org',
    'wp.com', 'wordpress.org', 'gravatar.com',
    'use.fontawesome.com', 'kit.fontawesome.com', 'fonts.shopifycdn.com',
    'youtube.com', 'vimeo.com', 'linkedin.com', 'instagram.com'
)


def _cdn_whitelist_match(host, cdn):
    """CLS-01z round-4: matching per SUFFISSO DI DOMINIO su host pieni,
    unico confronto — le voci-frammento che richiedevano `startswith`/label-
    nudo sono state eliminate da `_DEAD_MARKUP_CDN_WHITELIST` (v. sopra), non
    serve più distinguere la forma della voce. `fontawesome.xyz` non è né
    uguale né suffisso di `fontawesome.com`/`use.fontawesome.com` (TLD
    diverso): resta flaggato. `fonts.evil.example` non è suffisso di alcun
    host della whitelist: resta flaggato. `youtube.com.evil.example` non è
    né uguale né suffisso di `youtube.com`: resta flaggato, comportamento
    preesistente invariato."""
    return host == cdn or host.endswith('.' + cdn)


# CLS-01z round-5: parti statiche di `_dead_markup_url_host`, compilate una
# volta sola. Trim/normalizzazione sono quelli dello URL parser WHATWG (lo
# stesso del browser): C0 e spazio tolti agli estremi, tab/LF/CR tolti
# OVUNQUE, `\` letto come `/`.
_URL_TRIM_CHARS = "".join(chr(c) for c in range(0x21))
_URL_NORMALIZE = str.maketrans({"\t": None, "\n": None, "\r": None, "\\": "/"})
# Inizio dell'authority: `http`/`https` + ":" + 0-n slash (`http:host`,
# `http:/host`, `http:///host` sono tutti host assoluti per il browser), oppure
# nessuno schema e "//" (protocol-relative). Qualunque altro schema o URL
# relativo non ha host: nessun match.
_URL_AUTHORITY_START = re.compile(r'(?:https?:/*|//+)', re.IGNORECASE)
_URL_AUTHORITY_END = re.compile(r'[/?#]')


def _dead_markup_url_host(url):
    """CLS-01z round-5: host che il browser contatterebbe per `url`, o None se
    l'URL non ne ha uno (relativo, schema diverso da http/https, host vuoto).
    Il round 4 estraeva l'host con `https?://([^/]+)`: bastava un `#`, un `?`,
    un `\\`, uno `user:pw@` o uno slash in meno/in più per far leggere al
    detector un host diverso da quello del browser, e quindi aggirare la
    whitelist CDN o l'esclusione del dominio cliente con un solo carattere.
    Qui si segue la grammatica WHATWG; `urllib.parse.urlsplit` non è
    equivalente (non converte `\\`, non ignora gli slash extra, non legge
    `http:host`) e non viene usato.

    Falso positivo fail-safe dichiarato: `http:host` senza slash su una pagina
    `http` è per WHATWG un percorso relativo, ma qui lo schema della pagina
    non è noto e lo si tratta come host esterno."""
    s = (url or "").strip(_URL_TRIM_CHARS).translate(_URL_NORMALIZE)
    m = _URL_AUTHORITY_START.match(s)
    if not m:
        return None
    rest = s[m.end():]
    end = _URL_AUTHORITY_END.search(rest)
    authority = rest[:end.start()] if end else rest
    # L'host è dopo l'ULTIMA "@": tutto ciò che precede (anche con ":" o con
    # il testo di un altro host) è userinfo e non viene contattato.
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        # IPv6 letterale: i ":" interni non separano la porta, e `_strip_www`
        # lo spezzerebbe al primo.
        close = hostport.find("]")
        host = (hostport[:close + 1] if close != -1 else hostport).lower()
    else:
        host = _strip_www(hostport)
    # Il punto finale ("legit.example.") è lo stesso host per il DNS.
    if host.endswith("."):
        host = host[:-1]
    return host or None


def _dead_markup_external_host(url, self_domain_stripped):
    """Stesso criterio di "esterno" già usato per `external_resources`
    (sezione 8 di `detect_hidden_elements`): host diverso dal `self_domain` e
    da ogni suo sottodominio. L'host è quello che contatta il browser
    (`_dead_markup_url_host`): `//host` è esterno (decisione utente,
    2026-10-21) e così `http:host` senza slash, anche se su una pagina `http`
    WHATWG lo leggerebbe come relativo (falso positivo fail-safe). Un URL
    senza host (relativo, o con schema diverso da http/https) non è mai
    "esterno" — non c'è un host da valutare.
    CLS-01z round-4 (falso negativo frammenti): un host della whitelist CDN
    ANCORATA (`_DEAD_MARKUP_CDN_WHITELIST`, solo host pieni) o un suo
    sottodominio non è "esterno" ai fini di questo detector — whitelist
    separata da quella di `external_resources`, v. sopra."""
    host = _dead_markup_url_host(url)
    if host is None:
        return None
    if self_domain_stripped and (host == self_domain_stripped
                                  or host.endswith("." + self_domain_stripped)):
        return None
    if any(_cdn_whitelist_match(host, cdn) for cdn in _DEAD_MARKUP_CDN_WHITELIST):
        return None
    return host


def _dead_markup_url(tag_name, attrs):
    # Ambiguità #1 (G3): il nome del campo URL non è vincolato dai test.
    # Risolta rispecchiando le categorie sorelle stesse — `hidden_forms`
    # espone `action`, `invisible_iframes`/`tracking_pixels` espongono
    # `src` — non un nome nuovo comune a tutti e tre i tipi.
    return attrs.get("action") if tag_name == "form" else attrs.get("src")


def _dead_markup_entry(tag_name, url, source):
    """Un elemento di `suspicious_dead_markup`, nella forma delle categorie
    sorelle (`invisible_iframes`/`tracking_pixels` -> `src`, `hidden_forms`
    -> `action`)."""
    entry = {"type": tag_name, "source": source}
    entry["action" if tag_name == "form" else "src"] = _cap_ioc(url)
    return entry


def _collect_dead_markup(collector, self_domain):
    """CLS-01z, ristretto al solo caso (a) (decisione utente, round-3): markup
    iframe/form/img morto verso host esterno raccolto come fallback content
    opaco. `collector` è il `_TagCollector` già alimentato con l'intero
    `html` dal chiamante (`detect_hidden_elements`, prima della sezione 2)
    — nessun nuovo parsing del documento qui."""
    _self = _strip_www(self_domain)
    dead = []

    # ── Caso (a): fallback content opaco ──
    for t in collector.tags:
        # CLS-01u: il collector raccoglie anche gli `<input>`, che non sono markup morto.
        if not t["_opaque"] or t["name"] not in _DEAD_MARKUP_TAGS:
            continue
        url = _dead_markup_url(t["name"], t["attrs"])
        host = _dead_markup_external_host(url, _self)
        if host is None:
            continue
        dead.append(_dead_markup_entry(t["name"], url, "fallback_content"))
        # Cap coerente con `external_resources` (sezione 8): stesso principio
        # (limite di volume sull'output, non un criterio nuovo). Il ciclo si
        # ferma qui invece di tagliare dopo: un `[:20]` finale limitava
        # l'output ma non il lavoro, che su 2 MB di markup morto denso
        # valutava l'host di decine di migliaia di tag (G6 round-4, rilievo 6).
        if len(dead) == 20:
            break
    return dead


# CLS-01t: CPython limita la lunghezza delle cifre convertibili con `int()`
# (protezione nativa anti-DoS, `sys.get_int_max_str_digits()`, default
# 4300) e solleva `ValueError` oltre quella soglia. Letta una sola volta:
# la guardia in `_parse_dimension` confronta la lunghezza PRIMA di chiamare
# `int()`, non la avvolge in un try/except (che nasconderebbe il problema
# invece di prevenirlo).
# CLS-01t (rilievo MEDIA, G6 round 3): `0` è il valore sentinella documentato
# da CPython per `PYTHONINTMAXSTRDIGITS`/`sys.set_int_max_str_digits` che
# significa "nessun limite", non "zero cifre ammesse" — va trattato come tale
# nella guardia sotto, altrimenti `len(digits) > 0` scarta ogni cifra e
# disattiva l'intero rilevamento zero/one-px in silenzio.
_MAX_INT_DIGITS = sys.get_int_max_str_digits()


def _parse_dimension(value):
    """CLS-01r: HTML5 "rules for parsing dimension values" — l'algoritmo
    usato dagli attributi presentazionali `width`/`height`, NON le "rules
    for parsing non-negative integers" (quelle di `colspan`/`rowspan`/
    `size`, erroneamente citate nella prima stesura di questo criterio).
    La parte intera è la sequenza di cifre ASCII iniziali; se seguita da un
    punto e da un'altra cifra, il valore viene arrotondato per eccesso
    (round-half-up) sulla SOLA prima cifra frazionaria — "0.5" -> 1,
    "1.5" -> 2 — poi classificato pixel o percentuale a seconda che sia
    seguito da "%". Questa parte è conformità reale alla spec.
    CLS-01t: se la sola parte intera supera `_MAX_INT_DIGITS` cifre, la
    guardia evita del tutto `int()` — un prefisso così lungo non potrà mai
    valere 0 o 1 (gli unici esiti che contano ai chiamanti), quindi trattarlo
    come "nessun prefisso valido" (`None`) è sicuro. `_MAX_INT_DIGITS == 0`
    è la sentinella CPython per "nessun limite" (non "zero cifre ammesse"):
    la guardia va saltata in quel caso, non applicata come se fosse 0.
    Ritorna `{"value": int, "rounded": bool, "percent": bool}`, oppure
    `None` se il valore non inizia (dopo spazi iniziali) con una cifra.
    """
    if value is None:
        return None
    match = re.match(r"\s*(\d+)(\.(\d))?", value)
    if not match:
        return None
    digits = match.group(1)
    if _MAX_INT_DIGITS and len(digits) > _MAX_INT_DIGITS:
        return None
    n = int(digits)
    rounded = match.group(2) is not None
    if rounded and match.group(3) >= "5":
        n += 1
    percent = value[match.end():].strip().startswith("%")
    return {"value": n, "rounded": rounded, "percent": percent}


def _is_zero_or_one_px(value):
    """CLS-01b/CLS-01r: vero se il valore, letto secondo `_parse_dimension`,
    risolve a 0 o 1 — pixel assoluto o arrotondato.
    ⚠️ Divergenza deliberata dalla spec (decisione utente 2026-07-28, SCELTA
    DI POSTURA DI PRODOTTO, non conformità): quando il risultato è una
    PERCENTUALE (es. "1%"), la spec non lo tratterebbe come un pixel — una
    percentuale non ha una dimensione fissa nota — ma qui la trattiamo
    comunque come sospetta se risolve a 0/1, per preservare il richiamo su
    un vettore usato da kit di phishing reali. Chi chiama deve riportare
    una motivazione distinta per questo caso (v. `_zero_dimension_technique`)."""
    info = _parse_dimension(value)
    return info is not None and info["value"] in (0, 1)


def _is_one_px(value):
    """CLS-01i/CLS-01r: come `_is_zero_or_one_px` ma richiede ESATTAMENTE 1
    — lo 0 resta fuori (un'immagine 0x0 non è un pixel di tracciamento, è
    invisibilità: semantica del ramo iframe). Stessa divergenza deliberata
    sulle percentuali descritta sopra — v. `_pixel_technique`."""
    info = _parse_dimension(value)
    return info is not None and info["value"] == 1


def _zero_dimension_technique(width, height):
    """Motivazione (`technique`) per `invisible_iframes` quando width o
    height risolve a 0/1. CLS-01r bloccante 3 (G6 round 2): un valore
    ottenuto per arrotondamento da un decimale (es. "0.5" -> 1px REALE e
    visibile) non deve condividere la stessa motivazione di un valore
    letterale identico (es. "0" -> davvero 0x0) — altrimenti l'analista non
    può distinguere un falso positivo da un iframe genuinamente invisibile.
    CLS-01r (rilievo MEDIA, G6 round 3): stessa distinzione già presente sul
    ramo `<img>` (`_pixel_technique`) ora anche qui — un valore percentuale
    (es. "1%") non è un 1px/0px assoluto reale, è l'euristica di prodotto su
    percentuale decisa dall'utente il 2026-07-28 (v. `_is_zero_or_one_px`);
    la combinazione arrotondato+percentuale (es. "0.5%") ha una motivazione
    propria, distinta sia dal solo arrotondamento sia dalla sola percentuale.
    Vince il primo fra width e height il cui prefisso combacia; `None` se
    nessuno dei due risolve a 0/1."""
    for v in (width, height):
        info = _parse_dimension(v)
        if info is not None and info["value"] in (0, 1):
            if info["rounded"] and info["percent"]:
                return "zero_dimension_rounded_percent"
            if info["percent"]:
                return "zero_dimension_percent"
            if info["rounded"]:
                return "zero_dimension_rounded"
            return "zero_dimension"
    return None


def _pixel_technique(width, height):
    """Motivazione (`technique`) per `tracking_pixels`. Se il valore che ha
    determinato la rilevazione è una percentuale (es. "1%"), la motivazione
    lo dichiara esplicitamente: non è un 1px assoluto reale, è l'euristica
    di prodotto su percentuale decisa dall'utente il 2026-07-28 (v.
    `_is_one_px`) — l'analista non deve poterla confondere con un 1px
    assoluto genuino."""
    for v in (width, height):
        info = _parse_dimension(v)
        if info is not None and info["percent"]:
            return "pixel_1x1_percent_heuristic"
    return "pixel_1x1"


_CONTROL_CHARS = re.compile(r"[\x00-\x1F\x7F]")


def _cap_ioc(value):
    """R1 del security-reviewer (CLS-01i) + CLS-01s: src/action sono
    stringhe attacker-controlled che finiscono nello snapshot persistito.
    CR/LF e caratteri di controllo (categoria Cc, \\x00-\\x1F, \\x7F) vengono
    rimossi prima del tetto già applicato ai campi testuali
    (`snippet[:300]`, `tag[:300]`). None resta None: distingue l'attributo
    assente dal valore vuoto."""
    if value is None:
        return None
    return _CONTROL_CHARS.sub("", value)[:300]


# SEC-47: una pagina può moltiplicare questi elementi a decine di migliaia, e le liste finiscono nella risposta di
# /http, negli snapshot e nelle richieste al classificatore. 100 sta sopra la lista più lunga misurata su pagine
# ricostruite da forme reali (80 blocchi base64).
_HIDDEN_LIST_CAP = 100
_CAPPED_HIDDEN_LISTS = ("hidden_inputs", "hidden_forms", "invisible_iframes", "tracking_pixels", "meta_redirects",
                        "obfuscated_js", "hidden_divs_with_content", "large_comments", "base64_content")


def detect_hidden_elements(html: str, self_domain: str = None) -> dict:
    """
    Rileva tag nascosti e contenuto offuscato in HTML.
    Identifica infrastruttura offensiva preparata ma non visibile:
    hidden forms, invisible iframes, tracking pixels, meta redirect,
    JS offuscato, commenti con codice staged, data exfiltration.

    self_domain: se fornito, le risorse ospitate sullo stesso dominio (o suoi
    sottodomini) NON vengono contate come "esterne" — un sito che carica i propri
    /wp-content/... non è un indicatore di rischio.
    """
    findings = {
        "hidden_inputs": [],
        "hidden_forms": [],
        "invisible_iframes": [],
        "tracking_pixels": [],
        "suspicious_dead_markup": [],
        "meta_redirects": [],
        "obfuscated_js": [],
        "hidden_divs_with_content": [],
        "external_resources": [],
        "large_comments": [],
        "base64_content": [],
        "risk_indicators": 0,
        "summary": []
    }
    # Normalizza il dominio del sito stesso (per escludere risorse self-hosted)
    _self = _strip_www(self_domain)

    # SEC-48: un solo parsing per form, iframe, img e markup morto invece di uno per insieme di tag. I tag non opachi
    # di un nome sono quelli di un parsing dedicato: le regioni opache dipendono solo dagli `<iframe>`, non dai tag
    # richiesti. I tag opachi si scartano a ogni uso, non nel collector: restano nella sua lista finché il parsing non
    # stabilisce se l'iframe che li contiene si chiude. Col parser a costo limitato si assegna il buffer e si chiama
    # solo `close` (la prova all'import ne ha verificato l'uso): `feed` si fermerebbe su un tag che non si chiude e
    # `close` lo leggerebbe di nuovo da capo.
    # CLS-01u: lo stesso parsing raccoglie anche gli `<input>`.
    dead_markup_collector = _TagCollector(_DEAD_MARKUP_TAGS + ("input",))
    if _HTML_PARSER_FALLBACK is None:
        dead_markup_collector.rawdata = html
    else:
        dead_markup_collector.feed(html)
    dead_markup_collector.close()

    # ── 1. Hidden input fields ──
    # CLS-01u: dal tokenizer, come form, iframe e pixel. La scansione testuale chiudeva il tag al primo `>` anche
    # dentro un valore quotato (l'input dopo spariva), troncava nome e valore al primo spazio o apice, e contava
    # `type=hidden` anche dentro un altro attributo o in un `type` ripetuto, che il browser ignora.
    for inp in (t for t in dead_markup_collector.tags if t["name"] == "input" and not t["_opaque"]):
        attrs = inp["attrs"]
        if (attrs.get("type") or "").lower() != "hidden":
            continue
        value = _cap_ioc(attrs.get("value"))
        findings["hidden_inputs"].append({
            "tag": inp["text"][:200],
            "name": _cap_ioc(attrs.get("name")),
            "value": value[:100] if value is not None else None,
        })

    # ── 2. Hidden forms (display:none, visibility:hidden, opacity:0) ──
    # CLS-01h: stessa migrazione del punto 3 (CLS-01g) — i vecchi pattern regex
    # richiedevano un `</form>` letterale, quindi un form self-closing in stile
    # XHTML non veniva mai rilevato, qualunque tecnica di nascondimento avesse.
    # Il tokenizer emette il tag di apertura sia chiuso sia self-closing; il
    # nascondimento è un fatto del solo tag di apertura, il contenuto non serve.
    for form in (t for t in dead_markup_collector.tags if t["name"] == "form" and not t["_opaque"]):
        attrs = form["attrs"]
        style = attrs.get("style") or ""
        is_hidden = bool(re.search(
            r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0',
            style, re.IGNORECASE))
        # Parità col vecchio quarto pattern: "hidden" come sottostringa del
        # valore di `class` — l'ancoraggio al token è un difetto a sé (CLS-01m),
        # non va corretto qui di soppiatto.
        if not is_hidden:
            is_hidden = "hidden" in (attrs.get("class") or "").lower()
        technique = "css_hidden"
        # CLS-01p: l'attributo booleano `hidden` nasconde il form con qualunque valore, anche vuoto.
        if not is_hidden and "hidden" in attrs:
            is_hidden, technique = True, "hidden_attribute"
        if is_hidden:
            findings["hidden_forms"].append({
                "snippet": form["text"][:300],
                "action": _cap_ioc(attrs.get("action")),
                "technique": technique
            })

    # ── 3. Invisible iframes ──
    # CLS-01g (3° giro): la grammatica regex per-attributo del giro precedente
    # falliva l'INTERO match del tag su qualunque attributo fuori grammatica
    # (valore non quotato con '=' di querystring, '=' orfano, apice nel
    # valore) — falsi negativi totali, alcuni peggiori del bug originale.
    # Sostituita con `HTMLParser` della stdlib: gli attributi arrivano già
    # strutturati (quotati/non quotati/malformati, come li interpreta un
    # browser) invece di essere ri-derivati con una seconda grammatica regex.
    # CLS-01z/SEC-48: gli iframe vengono dal parsing unico prima della
    # sezione 2, su `_DEAD_MARKUP_TAGS` (iframe/form/img), lo stesso che
    # usano form, pixel e (sezione 4bis) `_collect_dead_markup` per il caso
    # (a) fallback content. Filtrati per nome e non opachi sono gli stessi
    # di un parsing dedicato agli iframe (stessa logica di raccolta/opacità
    # di `_TagCollector`, invariata).
    iframe_tags = [t for t in dead_markup_collector.tags
                   if t["name"] == "iframe" and not t["_opaque"]]
    for iframe in iframe_tags:
        attrs = iframe["attrs"]
        tag_text = iframe["text"]
        is_hidden = False
        technique = []

        # Dimensioni 0/1px — CLS-01b/CLS-01r: "rules for parsing dimension
        # values" (arrotondamento sulla prima cifra frazionaria); la
        # motivazione riportata distingue un valore letterale da uno
        # arrotondato (vedi _zero_dimension_technique).
        zero_dim_technique = _zero_dimension_technique(attrs.get("width"), attrs.get("height"))
        if zero_dim_technique:
            is_hidden = True
            technique.append(zero_dim_technique)
        # display:none / visibility:hidden / opacity:0 — regex ammessa qui:
        # non serve più delimitare il tag, il valore di `style` è già estratto.
        style = attrs.get("style") or ""
        if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0', style, re.IGNORECASE):
            is_hidden = True
            technique.append("css_hidden")
        # Position absolute con negative offset
        if re.search(r'(left|top)\s*:\s*-\d{3,}', style, re.IGNORECASE):
            is_hidden = True
            technique.append("offscreen")
        # CLS-01p: attributo booleano `hidden`, come per i form.
        if "hidden" in attrs:
            is_hidden = True
            technique.append("hidden_attribute")

        if is_hidden:
            findings["invisible_iframes"].append({
                "tag": tag_text[:300],
                "src": _cap_ioc(attrs.get("src")),
                "technique": technique
            })

    # ── 4. Tracking pixels (1x1 img) ──
    # CLS-01i: stessa migrazione dei punti 2-3 (CLS-01g/h). La regex
    # `<img[^>]*>` troncava il tag al primo `>` anche dentro un valore
    # quotato (falso negativo totale su pixel reali); le regex a boundary
    # fisse sul tag intero agganciavano il duplicato morto di `width` (il
    # browser tiene il PRIMO valore) o `data-src` (decoy inerte: `src\s*=`
    # non ancorava il nome dell'attributo); l'estrazione `[^"\'>\s]+`
    # troncava la src a spazi/apici interni consegnando IOC inesistenti.
    # Il tokenizer espone gli attributi come li interpreta un browser.
    for img in (t for t in dead_markup_collector.tags if t["name"] == "img" and not t["_opaque"]):
        attrs = img["attrs"]
        if _is_one_px(attrs.get("width")) and _is_one_px(attrs.get("height")):
            findings["tracking_pixels"].append({
                "tag": img["text"][:200],
                "src": _cap_ioc(attrs.get("src")),
                # CLS-01r: distingue un 1px assoluto reale da un 1px
                # ottenuto dall'euristica su percentuale (v. _pixel_technique).
                "technique": _pixel_technique(attrs.get("width"), attrs.get("height"))
            })

    # ── 4bis. CLS-01z: markup iframe/form/img morto verso host esterno ──
    # Discriminante primario è l'host esterno, NON un `AND` con
    # l'invisibilità (difetto concettuale bocciato dal verifier su
    # CLS-01w): un tag morto non è mai stato renderizzato per costruzione,
    # a grandezza qualunque. Per costruzione non si sovrappone alle tre
    # categorie sopra: quelle leggono solo i tag NON opachi del collector,
    # questa legge solo tag opachi (fallback content, caso (a) — unico caso
    # in scope dal round-3) — mai lo stesso tag in entrambi i canali.
    findings["suspicious_dead_markup"] = _collect_dead_markup(
        dead_markup_collector, self_domain)

    # ── 5. Meta refresh redirects ──
    for content in _meta_refresh_contents(html):
        url = re.search(r'url\s*=\s*(.*)', content, re.IGNORECASE)
        findings["meta_redirects"].append({
            "content": content[:200],
            "target_url": url.group(1).strip() if url else None,
            "delay": content.split(";")[0].strip() if ";" in content else content.strip()
        })

    # ── 6. Obfuscated JavaScript ──
    for _, content_start, content_end, _ in _tag_blocks(html, _SCRIPT_OPEN, _SCRIPT_CLOSE):
        js = html[content_start:content_end].strip()
        if not js:
            continue
        obfuscation_indicators = []

        if 'eval(' in js:
            obfuscation_indicators.append("eval")
        if 'atob(' in js:
            obfuscation_indicators.append("atob_base64")
        if 'document.write(' in js:
            obfuscation_indicators.append("document_write")
        if 'unescape(' in js or 'decodeURI(' in js:
            obfuscation_indicators.append("unescape")
        if 'String.fromCharCode' in js:
            obfuscation_indicators.append("fromCharCode")
        # Hex encoding massiccio
        hex_count = len(re.findall(r'\\x[0-9a-fA-F]{2}', js))
        if hex_count > 10:
            obfuscation_indicators.append(f"hex_encoding_{hex_count}")
        # Unicode encoding massiccio
        unicode_count = len(re.findall(r'\\u[0-9a-fA-F]{4}', js))
        if unicode_count > 10:
            obfuscation_indicators.append(f"unicode_encoding_{unicode_count}")
        # Array di numeri sospetto (char code obfuscation)
        if re.search(r'\[\s*\d+\s*(?:,\s*\d+\s*){20,}\]', js):
            obfuscation_indicators.append("charcode_array")
        # Variabili di singola lettera in massa (minified/obfuscated)
        if len(js) > 500 and len(set(re.findall(r'\b[a-z]\b', js))) > 15:
            # potrebbe essere solo minified, non obfuscated
            if 'eval' in js or 'atob' in js:
                obfuscation_indicators.append("minified_with_eval")

        if obfuscation_indicators:
            # unicode/hex encoding DA SOLI non indicano offuscamento malevolo:
            # i file WordPress (wp-emoji) e molti bundle minificati contengono
            # decine di sequenze \uXXXX legittime. Marca "offuscato" solo se c'è
            # un segnale di vera offuscazione (eval/atob/fromCharCode/document.write/
            # unescape/charcode_array/minified_with_eval), oppure encoding + uno di questi.
            strong = {"eval", "atob_base64", "document_write", "unescape",
                      "fromCharCode", "charcode_array", "minified_with_eval"}
            has_strong = any(ind in strong for ind in obfuscation_indicators)
            only_encoding = all(ind.startswith("hex_encoding") or ind.startswith("unicode_encoding")
                                for ind in obfuscation_indicators)
            if has_strong or not only_encoding:
                findings["obfuscated_js"].append({
                    "snippet": js[:300],
                    "length": len(js),
                    "indicators": obfuscation_indicators
                })

    # ── 7. Hidden divs with content ──
    hidden_div_scans = [
        (_STYLE_ATTR, _DISPLAY_NONE),
        (_STYLE_ATTR, _VISIBILITY_HIDDEN),
        (_CLASS_ATTR, _HIDDEN_WORD),
    ]
    div_closers = [m.start() for m in _DIV_CLOSE.finditer(html)]
    for attr_re, value_re in hidden_div_scans:
        for start, content_start, content_end, end in _hidden_div_blocks(html, attr_re, value_re, div_closers):
            inner = html[content_start:content_end].strip()
            # Solo se il div nascosto contiene contenuto significativo
            visible_text = _replace_tags(inner, '').strip()
            if len(visible_text) > 20:
                findings["hidden_divs_with_content"].append({
                    "snippet": html[start:end][:400],
                    "visible_text_preview": visible_text[:200],
                    "text_length": len(visible_text),
                    "contains_form": bool(re.search(r'<form', inner, re.IGNORECASE)),
                    "contains_input": bool(re.search(r'<input', inner, re.IGNORECASE)),
                    "contains_link": bool(re.search(r'<a\s', inner, re.IGNORECASE)),
                })

    # ── 8. External resources da domini terzi ──
    def _host_of(u):
        m = re.match(r'https?://([^/]+)', u, re.IGNORECASE)
        return _strip_www(m.group(1)) if m else ""
    ext_resources = set()
    for attr in ['src', 'href', 'action', 'data']:
        for m in re.finditer(rf'{attr}\s*=\s*["\']?(https?://[^"\'>\s]+)', html, re.IGNORECASE):
            url = m.group(1)
            host = _host_of(url)
            # Escludi risorse self-hosted: stesso dominio o suo sottodominio.
            # Un sito che carica i propri /wp-content/, /assets/... non è "esterno".
            if _self and (host == _self or host.endswith("." + _self)):
                continue
            ul = url.lower()
            # Escludi CDN noti e risorse standard (inclusi CDN WordPress/font comuni)
            # CLS-01z round-4: `_CDN_WHITELIST` non è più condivisa con
            # `_dead_markup_external_host` (che ora usa la whitelist ancorata
            # separata `_DEAD_MARKUP_CDN_WHITELIST`) — questa sezione resta
            # sullo stesso confronto largo `safe in url` di prima, invariato.
            if not any(safe in ul for safe in _CDN_WHITELIST):
                ext_resources.add(url)
    findings["external_resources"] = list(ext_resources)[:20]

    # ── 9. Large HTML comments (staged code) ──
    for start, end in _comment_blocks(html):
        content = html[start + len('<!--'):end - len('-->')].strip()
        if len(content) > 200:
            has_tags = bool(re.search(r'<\w+', content))
            has_js = bool(re.search(r'function\s|var\s|document\.|window\.', content))
            findings["large_comments"].append({
                "length": len(content),
                "preview": content[:200],
                "contains_html_tags": has_tags,
                "contains_javascript": has_js
            })

    # ── 10. Base64 encoded content inline ──
    # Cerca stringhe base64 lunghe (non in contesti normali come data:image per favicon)
    for start, b64 in _base64_blocks(html):
        findings["base64_content"].append({
            "length": len(b64),
            "preview": b64[:80] + "...",
            "context": html[max(0, start-30):start][-50:]
        })

    # ── Risk scoring ──
    risk = 0
    if findings["hidden_forms"]:
        risk += 30
        findings["summary"].append(f"{len(findings['hidden_forms'])} form nascosti — possibile credential harvesting")
    if findings["invisible_iframes"]:
        risk += 25
        findings["summary"].append(f"{len(findings['invisible_iframes'])} iframe invisibili — possibile contenuto malevolo embedato")
    if findings["suspicious_dead_markup"]:
        # Peso 30, deciso dall'utente (BUG-REGISTER.md, `CLS-01z`): pari a
        # `hidden_forms`, così un solo segnale attraversa la soglia
        # `suspicious`/HIGH (`classifier.py:365-382`, `>=30`).
        risk += 30
        findings["summary"].append(f"{len(findings['suspicious_dead_markup'])} markup morti sospetti verso host esterno — mai renderizzati per costruzione")
    if findings["obfuscated_js"]:
        risk += 20
        findings["summary"].append(f"{len(findings['obfuscated_js'])} script offuscati — indicatori: {', '.join(findings['obfuscated_js'][0].get('indicators', []))}")
    if findings["meta_redirects"]:
        risk += 20
        findings["summary"].append(f"Meta refresh verso: {findings['meta_redirects'][0].get('target_url', '?')}")
    if findings["hidden_inputs"] and len(findings["hidden_inputs"]) > 3:
        risk += 15
        findings["summary"].append(f"{len(findings['hidden_inputs'])} input nascosti — possibile form di raccolta dati")
    if findings["tracking_pixels"]:
        risk += 10
        findings["summary"].append(f"{len(findings['tracking_pixels'])} pixel di tracking")
    if findings["hidden_divs_with_content"]:
        for div in findings["hidden_divs_with_content"]:
            if div.get("contains_form"):
                risk += 25
                findings["summary"].append("Div nascosto contenente un form — alta probabilità di phishing preparato")
                break
        else:
            risk += 10
            findings["summary"].append(f"{len(findings['hidden_divs_with_content'])} div nascosti con contenuto")
    if findings["large_comments"]:
        for comm in findings["large_comments"]:
            if comm.get("contains_html_tags") or comm.get("contains_javascript"):
                risk += 15
                findings["summary"].append("Commenti HTML con codice stageable — possibile kit in attesa di attivazione")
                break
    if findings["base64_content"]:
        risk += 15
        findings["summary"].append(f"{len(findings['base64_content'])} blocchi base64 inline")

    findings["risk_indicators"] = min(risk, 100)

    # Tetto alle liste solo dopo rischio e `summary`, che restano della pagina intera; il totale di una lista
    # tagliata resta leggibile in `truncated`.
    truncated = {}
    for key in _CAPPED_HIDDEN_LISTS:
        items = findings[key]
        if len(items) <= _HIDDEN_LIST_CAP:
            continue
        truncated[key] = len(items)
        kept = items[:_HIDDEN_LIST_CAP]
        if key == "hidden_divs_with_content":
            # L'alert `legit_content_injected` del classificatore nasce dal primo div con form o input: se sta oltre
            # il tetto prende l'ultimo posto, così l'alert resta quello della pagina intera.
            first = next((i for i, div in enumerate(items) if div["contains_form"] or div["contains_input"]), None)
            if first is not None and first >= _HIDDEN_LIST_CAP:
                kept[-1] = items[first]
        findings[key] = kept
    if truncated:
        findings["truncated"] = truncated

    # Pulizia: rimuovi liste vuote per output leggibile
    findings = {k: v for k, v in findings.items() if v or k in ("risk_indicators", "summary")}

    return findings


# ═══════════════════════════════════════════════════════════════
# Hashing
# ═══════════════════════════════════════════════════════════════

def content_hash(content: bytes | str) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    return hashlib.sha256(content).hexdigest()


# ═══════════════════════════════════════════════════════════════
# Time helpers
# ═══════════════════════════════════════════════════════════════

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_check_due(last_checked_iso: str | None, hours: int) -> bool:
    if not last_checked_iso:
        return True
    try:
        last_dt = datetime.fromisoformat(last_checked_iso)
        return (datetime.now(timezone.utc) - last_dt) >= timedelta(hours=hours)
    except (ValueError, TypeError):
        return True


# ═══════════════════════════════════════════════════════════════
# Stato dei moduli di raccolta (CODE-14 / CODE-15)
# ═══════════════════════════════════════════════════════════════

def collection_failed(value) -> bool:
    """True se il dict prodotto da un collector rappresenta un fallimento della
    raccolta (non un dato reale, anche vuoto). Punto unico di verità condiviso
    da `orchestrator._module_failed` (canale alert/baseline, CODE-01/CODE-14) e
    da `classifier.classify_variant` (canale case, CODE-15): senza una sola
    funzione le due letture rischiano di divergere sulla stessa domanda
    ("questo modulo ha raccolto qualcosa?").

    Tre forme reali (lette dal sorgente dei collector, non un fixture
    idealizzato tipo `{"error": "timeout"}`):
    - whois_intel.py / cert_intel.py: `error` top-level popolato.
    - reputation.py (CODE-14): `error` top-level resta sempre `None`; il
      guasto vive annidato in virustotal/otx/securitytrails.error quando le
      fonti interrogate falliscono TUTTE.
    - http_fingerprint.py: `error` top-level resta sempre `None`; il segnale
      è `overall_status` in ("down", "error"), con ogni check reale che porta
      comunque una chiave `error` (valorizzata o `None`, ma presente — è il
      collector stesso a scriverla sempre, riga 76). Un dict `checks` senza
      quella chiave non è l'output del collector: è un fixture di test per
      un'altra asserzione (es. `test_none_content_length_no_crash`), non va
      confuso con un guasto reale.
      ATTENZIONE (misurato su un insieme di snapshot reali, CODE-15): uno
      `status_code` valorizzato — anche >= 400 — è SEMPRE una risposta HTTP
      reale (il ramo `overall_status == "error"` lo richiede per costruzione),
      e il prefisso `"blocked (SSRF protection)"` / `"blocked redirect (SSRF
      protection)"` su `error` è un fatto misurato sul dominio (non risolve),
      aggiunto deliberatamente da `is_safe_url`. Nessuno dei due è un guasto
      del collector: un check con l'uno o l'altro non conta per il fallimento.

    Non decide nulla su `value is None`: chi chiama sceglie il significato di
    "assente" (per l'orchestrator un modulo mai risposto è un fallimento, per
    il classificatore un modulo non richiesto in quel ciclo non lo è).
    """
    if not isinstance(value, dict):
        return False
    # SCO-05 (R3, round 4). `error` top-level è scritto SOLO dentro un ramo di
    # eccezione (whois_intel.py:107, cert_intel.py:136 — via `sanitize_error`)
    # o di errore HTTP esplicito, mai come default di successo (il default è
    # sempre `None`, mai `""`): `sanitize_error(e)` su un'eccezione senza
    # messaggio (`str(e) == ""`) produce una stringa vuota ma PRESENTE, che un
    # controllo di verità (`if value.get("error"):`) legge come "non fallito"
    # — la stessa classe di difetto "assente ≠ fallito" (CODE-01), qui sul
    # valore anziché sulla chiave. La chiave è presente solo su un fallimento
    # reale, quindi il discriminante corretto è la presenza, non la verità.
    if "error" in value and value["error"] is not None:
        return True
    sources = (value.get("virustotal"), value.get("otx"), value.get("securitytrails"))
    checked = [s for s in sources if isinstance(s, dict)]
    if checked:
        return all(s.get("error") for s in checked)
    if "overall_status" in value:
        if value["overall_status"] not in ("down", "error"):
            return False
        checks = value.get("checks") or []
        if not (checks and all(isinstance(c, dict) and "error" in c for c in checks)):
            return False
        # Un check con status_code valorizzato o con il prefisso SSRF è una
        # lettura reale, non un buco di raccolta: se anche uno solo lo è, il
        # modulo non conta come fallito.
        return not any(
            c.get("status_code") is not None or
            (isinstance(c.get("error"), str) and
             c["error"].startswith((SSRF_ERROR_PREFIX, SSRF_REDIRECT_ERROR_PREFIX)))
            for c in checks
        )
    return False


def reputation_source_unobserved(source) -> bool:
    """COL-16: True se una fonte della sezione `reputation` (`virustotal`, `otx`,
    `securitytrails`) in questo ciclo non ha osservato nulla: dict con `error` presente
    e non `None`. Il collector scrive una fonte guasta come un dict completo con i numeri
    a zero, e quegli zeri non sono una lettura. Come baseline o come ciclo corrente
    fanno uscire un alert per un valore osservato prima del guasto, oppure ne
    nascondono uno vero. Orchestrator (riporto della fonte precedente) e classificatore
    (`/diff`) rispondono alla stessa domanda con questa funzione, come per
    `collection_failed` a livello di modulo.

    Si decide per PRESENZA di `error`, non per la sua verità (SCO-05): un'eccezione senza
    messaggio dà `error: ""` via `sanitize_error`, un guasto come gli altri che un
    controllo di verità leggerebbe come osservato.

    L'esito 404 di VT (`VT_NOT_FOUND_ERROR`) è l'unica eccezione, ed è un'osservazione:
    VT ha risposto che non conosce il dominio, quindi gli zeri sono veri. Trattarlo da
    guasto riporterebbe un verdetto vecchio sopra un dato reale e farebbe tacere il
    passaggio 404 → malevolo, che è un cambiamento vero.

    Una fonte `None` (non interrogata: chiave assente o `sources=`) o che non è un dict
    non è un guasto di fonte: la regola non la riguarda."""
    if not isinstance(source, dict) or source.get("error") is None:
        return False
    return source["error"] != VT_NOT_FOUND_ERROR


def _calc_score(results: dict) -> int:
    score = 0
    vt = results.get("virustotal")
    if vt and not vt.get("error"):
        score += min(vt.get("malicious", 0) * 10, 50)
        score += min(vt.get("suspicious", 0) * 5, 20)
        if vt.get("reputation", 0) < -5:
            score += 10
    otx = results.get("otx")
    if otx and not otx.get("error"):
        score += min(otx.get("pulse_count", 0) * 5, 30)
        if otx.get("malware_families"):
            score += 20
    return min(score, 100)


def _score_to_level(score: int) -> str:
    if score == 0: return "clean"
    if score <= 20: return "low"
    if score <= 50: return "medium"
    if score <= 80: return "high"
    return "critical"
