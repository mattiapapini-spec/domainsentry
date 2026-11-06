"""SEC-29 — `GET /dns` ha una scadenza complessiva per richiesta.

Senza un orologio complessivo, `/dns` esegue i 7 tipi base in serie, poi DMARC, DKIM (3 giri da 8), BIMI, CAA e i
sottodomini (3 giri da 10, A poi CNAME): 19 stadi uno dopo l'altro, ciascuno fino a `DNS_TIMEOUT + 10` = 20 s con un
resolver che non risponde. La richiesta dell'orchestrator (`full=true&subdomains=true`, 18 selettori) dura così circa
380 s: l'orchestrator rinuncia a 45 s e registra `None`, mentre il gestore continua per minuti con un thread del pool e
fino a 10 processi `dig`. Con due tipi base muti e il resto rapido, i tipi dopo il secondo arrivano solo dopo 40 s.

Comportamento atteso (disegno deciso per SEC-29):

* una scadenza per richiesta, `services.dns_intel.DNS_DEADLINE_S` (40 s), letta a ogni chiamata e fissata quando la
  richiesta inizia;
* ogni `dig` è limitato al tempo che resta alla richiesta, anche quando parte tardi, ed è ucciso se è ancora in corso
  alla scadenza; dopo la scadenza non parte alcuna query nuova;
* ogni query non raggiunta o interrotta passa dal ramo `unknown` che esiste già (RES-01): mai omessa, mai `nodata`; i
  record ottenuti prima della scadenza restano nella risposta come dati di questa richiesta;
* `shared.utils.dig_lookup(fqdn, rtype, timeout, *, limit=None)`: `limit` è il tempo massimo in secondi dell'intera
  chiamata (con `limit <= 0` nessun processo, `unknown`): il processo vive al più `min(timeout + 10, limit)`, cioè il
  tetto per query quando il tempo che resta è lungo, il tempo che resta quando è più corto; `+time` resta l'intero
  `timeout` e `+tries` resta 2, quindi un resto frazionario non arriva mai a `dig`, che con `+time=1.5` esce subito
  senza interrogare nulla;
* i 7 tipi base partono insieme; i processi `dig` vivi nello stesso istante non sono mai più di 10, il picco del codice
  senza scadenza (stadio dei sottodomini);
* con un DNS che risponde, la risposta è identica a quella del codice senza scadenza, campo per campo e nell'ordine
  delle chiavi.

Isolamento: nessun `dig` reale e nessuna rete. Un `dig` finto (uno script Python scritto in una directory temporanea,
primo nel `PATH`) risponde da una zona finta nel formato registrato con `dig` 9.18.39 (vedi `tests/test_dns_intel.py`,
`_dig_stdout`), oppure resta muto, come un resolver che non risponde, finché il test non lo libera. Come `dig`, rifiuta
un `+time` o un `+tries` non interi (uscita 10). Ogni processo annota argv, istante di partenza e quanti `dig` finti
sono vivi in quel momento. Una guardia su `subprocess.Popen` annota l'istante di ogni avvio di `dig` e rifiuta
qualunque `dig` che non sia quello finto; resta installata finché una richiesta del modulo è in corso.

Tempi: per il test la scadenza scende a pochi secondi (attributo del modulo). Un `dig` muto non risponde mai da solo,
quindi senza la scadenza ogni query dura `DNS_TIMEOUT + 10` = 20 s. Si aspetta la risposta fino a scadenza + 6 s
(oltre, la richiesta è rossa e i `dig` muti vengono liberati, così finisce in pochi secondi e il test controlla che
non resti nulla); i test sullo sforo pretendono poi la risposta entro scadenza + 1 s (`_TIGHT_MARGIN_S`), un
margine più stretto dei 5 s che l'orchestrator lascia in produzione (45 s contro 40 s).
"""
import contextlib
import copy
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from services import dns_intel
from shared import utils
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

DOMAIN = "shop-lookalike.example"
_OTHER_DOMAIN = "other-lookalike.example"
_BASE = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
_SECTIONS = ["dmarc", "bimi", "caa"]

_DEADLINE_S = 2.0          # scadenza usata dai test (in produzione 40 s)
_MARGIN_S = 6.0            # oltre la scadenza: la risposta che arriva dopo è rossa
# Sforo massimo ammesso sulla scadenza. In produzione l'orchestrator aspetta 5 s oltre i 40 della scadenza: uno sforo
# fisso di qualche secondo, o un `dig` che parte tardi con l'intera scadenza (o con il tetto di 20 s) come limite,
# consegna `None`. Lo sforo vero è di centesimi di secondo (kill, attesa del processo, risposta), qualche decimo con
# la CPU satura: 1 s lo separa da qualunque errore di un secondo o più e resta sotto i 5 s di produzione.
_TIGHT_MARGIN_S = 1.0
_SETTLE_S = 0.3            # dopo la risposta, prima di ricontare i processi
_THREAD_GRACE_S = 2.0      # i thread della richiesta devono essere finiti entro questo tempo
_RELEASE_JOIN_S = 60.0     # una richiesta abbandonata, liberati i `dig`, deve finire entro questo tempo
_MAX_DIGS = 10             # il picco di `dig` contemporanei senza la scadenza (stadio dei sottodomini)

# L'argv di `dig_lookup` con `DNS_TIMEOUT` = 10, nome e tipo esclusi.
_DIG_OPTIONS = ["+noall", "+comments", "+answer", "+nottlid", "+noclass", "+ndots=1", "+time=10", "+tries=2",
                "+noidnout"]

_NODATA = ("NOERROR", ())
_SERVFAIL = ("SERVFAIL", ())
_NXDOMAIN = ("NXDOMAIN", ())
_REFUSED = ("REFUSED", ())
_TRANSPORT = ("TRANSPORT", ())     # il `dig` finto esce con 9: «connection refused», nessuna risposta


def _ok(*rdata):
    return ("NOERROR", rdata)


# ── Il `dig` finto ──────────────────────────────────────────────────────────────────────────────────────────

_FAKE_DIG = r'''#!@@PYTHON@@ -IS
# dig finto dei test SEC-29: nessuna rete. Risponde dalla zona di conf.json o resta muto fino alla liberazione.
import fcntl, json, os, sys, time

STATE = @@STATE@@
ME = @@ME@@
PARENT = os.getppid()


def _alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            state = f.read().rpartition(")")[2].split()[0]
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            cmdline = f.read()
    except OSError:
        return False
    return state != "Z" and ME.encode() in cmdline


def _note(**fields):
    fields.update(pid=os.getpid(), t=time.time())
    fd = os.open(os.path.join(STATE, "log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(fields) + "\n").encode())
    finally:
        os.close(fd)


def _released():
    # Liberato dal test, oppure orfano: un processo rimasto senza il suo pytest non resta appeso.
    return os.path.exists(os.path.join(STATE, "release")) or os.getppid() != PARENT


def _wait(seconds):
    """Attende `seconds` (None: senza fine) o la liberazione; True se liberato. Mai oltre 120 s."""
    start = time.monotonic()
    while not _released():
        elapsed = time.monotonic() - start
        if elapsed >= 120:
            return True
        if seconds is not None and elapsed >= seconds:
            return False
        time.sleep(0.02)
    return True


def _no_answer():
    sys.stdout.write(";; communications error to 127.0.0.1#53: timed out\n"
                     ";; communications error to 127.0.0.1#53: timed out\n"
                     ";; no servers could be reached\n")
    _note(ev="end", rc=9)
    sys.exit(9)


with open(os.path.join(STATE, "registry"), "a+") as reg:
    fcntl.flock(reg, fcntl.LOCK_EX)
    reg.seek(0)
    pids = [int(p) for p in reg.read().split() if _alive(int(p))] + [os.getpid()]
    reg.seek(0)
    reg.truncate()
    reg.write(" ".join(str(p) for p in pids))
    reg.flush()

argv = sys.argv[1:]
_note(ev="start", argv=argv, running=len(pids))
with open(os.path.join(STATE, "conf.json")) as f:
    conf = json.load(f)

for opt in ("time", "tries"):
    values = [a.split("=", 1)[1] for a in argv if a.startswith("+" + opt + "=")]
    if values and not values[-1].isdigit():
        sys.stderr.write("invalid %s '%s': not a valid number\ndig: Couldn't parse %s\n" % (opt, values[-1], opt))
        _note(ev="end", rc=10)
        sys.exit(10)

name, rtype = argv[-2], argv[-1]
if _released():
    _no_answer()
if any(h[0] in ("*", name) and h[1] in ("*", rtype) for h in conf["hang"]):
    _note(ev="hang")
    _wait(None)
    _no_answer()
delay = conf["delay"]
for d_name, d_type, d_seconds in conf["delays"]:
    if (d_name, d_type) == (name, rtype):
        delay = d_seconds
if delay and _wait(delay):
    _no_answer()
rcode, rdata = "NOERROR", []
for z_name, z_type, z_rcode, z_rdata in conf["zone"]:
    if (z_name, z_type) == (name, rtype):
        rcode, rdata = z_rcode, z_rdata
if rcode == "TRANSPORT":
    sys.stdout.write(";; communications error to 127.0.0.9#53: connection refused\n"
                     ";; communications error to 127.0.0.9#53: connection refused\n"
                     ";; no servers could be reached\n")
    _note(ev="end", rc=9)
    sys.exit(9)
out = (";; Got answer:\n"
       ";; ->>HEADER<<- opcode: QUERY, status: %s, id: 4242\n"
       ";; flags: qr aa rd ra; QUERY: 1, ANSWER: %d, AUTHORITY: 0, ADDITIONAL: 1\n"
       "\n"
       ";; OPT PSEUDOSECTION:\n"
       "; EDNS: version: 0, flags:; udp: 1232\n") % (rcode, len(rdata))
if rdata:
    out += ";; ANSWER SECTION:\n" + "".join("%s.\t\t%s\t%s\n" % (name, rtype, r) for r in rdata) + "\n"
sys.stdout.write(out)
_note(ev="end", rc=0)
'''


def _proc_alive(pid, marker):
    """Processo vivo (non zombie) con `marker` nella riga di comando: un pid riusato non conta."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            state = f.read().rpartition(")")[2].split()[0]
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read()
    except OSError:
        return False
    return state != "Z" and marker in cmdline


class _FakeDns:
    """Il `dig` finto, la sua zona e ciò che ha visto."""

    def __init__(self, root):
        root = pathlib.Path(root)
        self.state = root / "state"
        self.bin = root / "bin"
        self.state.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        self.dig = self.bin / "dig"
        self.dig.write_text(_FAKE_DIG.replace("@@PYTHON@@", sys.executable)
                            .replace("@@STATE@@", repr(str(self.state)))
                            .replace("@@ME@@", repr(str(self.dig))))
        self.dig.chmod(0o755)
        self.spawns = []        # (time.monotonic(), argv) di ogni `dig` avviato, dalla guardia
        self.foreign = []       # `dig` diversi da quello finto, rifiutati dalla guardia
        self.configure()

    def configure(self, zone=None, *, hang=(), delay=0.0, delays=None):
        """`zone`: {(nome, tipo): (rcode, rdata)}, il resto NODATA. `hang`: [(nome o "*", tipo o "*")] muti.
        `delay`: secondi prima di ogni risposta; `delays`: {(nome, tipo): secondi} per le singole query."""
        conf = {"zone": [[n, t, rcode, list(rdata)] for (n, t), (rcode, rdata) in (zone or {}).items()],
                "hang": [list(h) for h in hang], "delay": delay,
                "delays": [[n, t, seconds] for (n, t), seconds in (delays or {}).items()]}
        tmp = self.state / "conf.json.tmp"
        tmp.write_text(json.dumps(conf))
        os.replace(tmp, self.state / "conf.json")

    def reset(self):
        for name in ("log", "registry", "release"):
            (self.state / name).unlink(missing_ok=True)
        self.spawns.clear()

    def release(self):
        (self.state / "release").touch()

    def unrelease(self):
        (self.state / "release").unlink(missing_ok=True)

    def log(self):
        path = self.state / "log"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def peak(self):
        """Il massimo di `dig` finti vivi insieme, contato da ciascuno alla propria partenza."""
        return max((e["running"] for e in self.log() if e["ev"] == "start"), default=0)

    def alive(self):
        marker = str(self.dig).encode()
        return sorted(int(p) for p in os.listdir("/proc") if p.isdigit() and _proc_alive(int(p), marker))

    def kill_all(self):
        for pid in self.alive():
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


_REAL_POPEN = subprocess.Popen
_LIVE_THREADS = []      # richieste avviate dal modulo, anche abbandonate


def _guard_for(fake):
    """`subprocess.Popen` che annota ogni `dig` avviato e rifiuta qualunque `dig` diverso da quello finto (con
    `fake=None` li rifiuta tutti). Il rifiuto è un `OSError`: per `dig_lookup` una query senza esito."""
    class _GuardedPopen(_REAL_POPEN):
        def __init__(self, args, *rest, **kwargs):
            program = kwargs.get("executable") or (args[0] if isinstance(args, (list, tuple)) and args else args)
            if isinstance(program, (str, bytes, os.PathLike)) and os.path.basename(os.fsdecode(program)) == "dig":
                env = kwargs.get("env")
                path = env.get("PATH") if env is not None else os.environ.get("PATH")
                argv = [os.fsdecode(a) for a in args] if isinstance(args, (list, tuple)) else [os.fsdecode(args)]
                if fake is None or shutil.which(os.fsdecode(program), path=path) != str(fake.dig):
                    if fake is not None:
                        fake.foreign.append(argv)
                    raise OSError("test SEC-29: solo il dig finto può partire")
                fake.spawns.append((time.monotonic(), argv))
            super().__init__(args, *rest, **kwargs)
    return _GuardedPopen


def _join_threads(threads, timeout):
    end = time.monotonic() + timeout
    for th in threads:
        th.join(max(0.0, end - time.monotonic()))
    return [th for th in threads if th.is_alive()]


@contextlib.contextmanager
def _installed_fake(root):
    """Il `dig` finto primo nel `PATH`, la guardia su `subprocess.Popen`, `DNS_TIMEOUT` = 10. All'uscita libera i
    `dig` muti e attende ogni thread nato nel frattempo (richieste abbandonate, pool lasciati indietro): la guardia
    si toglie solo quando sono tutti finiti, altrimenti resta e rifiuta ogni `dig`, perché un thread rimasto non
    trovi mai il `dig` vero quando il `PATH` torna quello di prima."""
    fake = _FakeDns(root)
    mp = pytest.MonkeyPatch()
    previous_popen = subprocess.Popen
    before = set(threading.enumerate())
    leaked = []
    try:
        mp.setenv("PATH", f"{fake.bin}{os.pathsep}{os.environ.get('PATH', '')}")
        mp.setattr(dns_intel, "DNS_TIMEOUT", 10)
        subprocess.Popen = _guard_for(fake)
        assert shutil.which("dig") == str(fake.dig)
        yield fake, mp
    finally:
        fake.release()
        born = [th for th in threading.enumerate() if th not in before and th is not threading.current_thread()]
        leaked = _join_threads(born + _LIVE_THREADS, _RELEASE_JOIN_S)
        _LIVE_THREADS[:] = [th for th in _LIVE_THREADS if th.is_alive()]
        subprocess.Popen = _guard_for(None) if leaked else previous_popen
        mp.undo()
        deadline = time.monotonic() + 5
        while fake.alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        fake.kill_all()
    assert not leaked, f"thread ancora vivi dopo la liberazione dei dig: {sorted({t.name for t in leaked})}"
    assert not fake.foreign, f"dig diversi da quello finto (rifiutati): {fake.foreign[:3]}"


# ── Una richiesta /dns con un limite di tempo ────────────────────────────────────────────────────────────────

class _Outcome:
    def __init__(self, deadline, bound):
        self.deadline = deadline
        self.bound = bound
        self.elapsed = None             # None: nessuna risposta entro `bound`
        self.status = None
        self.body = None
        self.digs_at_response = []      # `dig` finti vivi al momento della risposta
        self.digs_after = []            # e `_SETTLE_S` dopo
        self.threads_after = []         # thread nati durante la richiesta e ancora vivi dopo `_THREAD_GRACE_S`
        self.spawns = []                # (secondi dall'inizio, argv senza "dig")
        self.log = []
        self.peak = 0

    def must_have_answered(self):
        assert self.elapsed is not None, (
            f"/dns non ha risposto entro {self.bound:.1f} s (scadenza {self.deadline} s): senza scadenza "
            "complessiva ogni query muta dura 20 s")
        assert self.status == 200, (self.status, self.body)
        return self.body


def _start(client, params, box):
    def call():
        try:
            box["response"] = client.get("/dns", params=params)
        except BaseException as exc:      # riportata al test
            box["error"] = exc
        finally:
            box["t"] = time.monotonic()
    th = threading.Thread(target=call, name="sec29-dns-request", daemon=True)
    _LIVE_THREADS.append(th)
    th.start()
    return th


def _request(fake, mp, params, deadline, *, bound=None):
    """GET /dns con `DNS_DEADLINE_S = deadline`; aspetta la risposta al più `bound` secondi."""
    mp.setattr(dns_intel, "DNS_DEADLINE_S", deadline, raising=False)
    fake.unrelease()
    fake.reset()
    out = _Outcome(deadline, deadline + _MARGIN_S if bound is None else bound)
    client = TestClient(dns_intel.app)
    box = {}
    before = set(threading.enumerate())
    t0 = time.monotonic()
    th = _start(client, params, box)
    th.join(out.bound)
    if th.is_alive():
        # Come l'orchestrator: si smette di aspettare. Liberati i `dig` muti, la richiesta finisce da sola.
        fake.release()
        th.join(_RELEASE_JOIN_S)
    else:
        out.elapsed = box["t"] - t0
        out.digs_at_response = fake.alive()
        time.sleep(_SETTLE_S)
        out.digs_after = fake.alive()
        end = time.monotonic() + _THREAD_GRACE_S
        while True:
            born = [t for t in threading.enumerate() if t not in before and t is not th and t.is_alive()]
            if not born or time.monotonic() >= end:
                break
            time.sleep(0.05)
        out.threads_after = [t.name for t in born]
        if "error" in box:
            raise box["error"]
        out.status = box["response"].status_code
        out.body = box["response"].json()
    out.spawns = [(t - t0, argv[1:]) for t, argv in list(fake.spawns)]
    out.log = fake.log()
    out.peak = fake.peak()
    fake.release()
    return out


def _params(path):
    return {"domain": DOMAIN, **{"base": {}, "full": {"full": "true"},
                                 "full+sub": {"full": "true", "subdomains": "true"}}[path]}


# ── La zona finta e la risposta del codice senza scadenza ───────────────────────────────────────────────────

def _dkim(sel):
    return f"{sel}._domainkey.{DOMAIN}"


def _sub(label):
    return f"{label}.{DOMAIN}"


_ZONE = {
    (DOMAIN, "A"): _ok("192.0.2.11", "192.0.2.10"),
    (DOMAIN, "AAAA"): _ok("2001:db8::10"),
    (DOMAIN, "MX"): _ok(f"10 mail.{DOMAIN}."),
    (DOMAIN, "NS"): _ok(f"ns2.{DOMAIN}.", f"ns1.{DOMAIN}."),
    (DOMAIN, "TXT"): _ok('"v=spf1 -all"', '"hello world"'),
    (DOMAIN, "SOA"): _ok(f"ns1.{DOMAIN}. hostmaster.{DOMAIN}. 2026010101 7200 900 1209600 3600"),
    (DOMAIN, "CAA"): _ok('0 issue "ca.example"'),
    (f"_dmarc.{DOMAIN}", "TXT"): _ok('"v=DMARC1; p=reject"'),
    (f"default._bimi.{DOMAIN}", "TXT"): _ok(f'"v=BIMI1; l=https://{DOMAIN}/logo.svg"'),
    (_dkim("google"), "TXT"): _ok('"v=DKIM1; k=rsa; p=KEY1"'),
    (_dkim("selector1"), "TXT"): _ok('"v=DKIM1; k=rsa; p=KEY2"'),
    (_sub("www"), "A"): _ok("192.0.2.20"),
    (_sub("mail"), "A"): _ok("192.0.2.21"),
    (_sub("autodiscover"), "CNAME"): _ok("autodiscover.provider.example."),
    (_sub("pop"), "A"): _NXDOMAIN,
}

# Risposte rapide ma negative o guaste: il ramo `unknown` esistente, senza alcuna scadenza in gioco.
_ZONE_FAST_FAILURES = {
    **_ZONE,
    (DOMAIN, "AAAA"): _SERVFAIL,
    (DOMAIN, "MX"): _NXDOMAIN,
    (DOMAIN, "TXT"): _TRANSPORT,
    (DOMAIN, "SOA"): _REFUSED,
    (DOMAIN, "CAA"): _TRANSPORT,
    (f"_dmarc.{DOMAIN}", "TXT"): _NXDOMAIN,
    (f"default._bimi.{DOMAIN}", "TXT"): _SERVFAIL,
    (_dkim("selector1"), "TXT"): _SERVFAIL,
    (_dkim("k1"), "TXT"): _TRANSPORT,
    (_sub("mail"), "A"): _SERVFAIL,
    (_sub("webmail"), "CNAME"): _TRANSPORT,
}

# Le risposte di `/dns` alla zona `_ZONE` registrate sul codice senza scadenza (`timestamp` escluso), con il suo ordine
# delle chiavi.
_HEALTHY_BASE = {
    "domain": DOMAIN,
    "records": {
        "A": ["192.0.2.10", "192.0.2.11"],
        "AAAA": ["2001:db8::10"],
        "MX": [f"10 mail.{DOMAIN}"],
        "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
        "TXT": ['"hello world"', '"v=spf1 -all"'],
        "SOA": [f"ns1.{DOMAIN}. hostmaster.{DOMAIN}. 2026010101 7200 900 1209600 3600"],
        "CNAME": [],
    },
    "records_status": {"A": "ok", "AAAA": "ok", "MX": "ok", "NS": "ok", "TXT": "ok", "SOA": "ok", "CNAME": "nodata"},
    "email_auth": {},
    "subdomains": {},
    "error": None,
}
_HEALTHY_EMAIL_AUTH = {
    "spf": {"present": True, "records": ['"v=spf1 -all"'], "policy": "fail", "status": "ok"},
    "dmarc": {"present": True, "records": ['"v=DMARC1; p=reject"'], "status": "ok"},
    "dkim": {"selectors_found": ["google", "selector1"], "selectors_tested": 18,
             "records": {"google": ['"v=DKIM1; k=rsa; p=KEY1"'], "selector1": ['"v=DKIM1; k=rsa; p=KEY2"']},
             "selectors_unknown": []},
    "bimi": {"present": True, "records": [f'"v=BIMI1; l=https://{DOMAIN}/logo.svg"'], "status": "ok"},
    "caa": {"present": True, "records": ['0 issue "ca.example"'], "status": "ok"},
}
_HEALTHY_SUBDOMAINS = {
    "tested": 25,
    "active": [{"fqdn": _sub("www"), "A": ["192.0.2.20"], "CNAME": []},
               {"fqdn": _sub("mail"), "A": ["192.0.2.21"], "CNAME": []},
               {"fqdn": _sub("autodiscover"), "A": [], "CNAME": ["autodiscover.provider.example"]}],
    "unknown": [],
}
_HEALTHY = {
    "base": _HEALTHY_BASE,
    "full": {**_HEALTHY_BASE, "email_auth": _HEALTHY_EMAIL_AUTH},
    "full+sub": {**_HEALTHY_BASE, "email_auth": _HEALTHY_EMAIL_AUTH, "subdomains": _HEALTHY_SUBDOMAINS},
}
# La stessa richiesta `full+sub` sulla zona `_ZONE_FAST_FAILURES`, registrata sul codice senza scadenza.
_FAST_FAILURES_BODY = {
    "domain": DOMAIN,
    "records": {"A": ["192.0.2.10", "192.0.2.11"], "AAAA": [], "MX": [], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
                "TXT": [], "SOA": [], "CNAME": []},
    "records_status": {"A": "ok", "AAAA": "unknown", "MX": "nxdomain", "NS": "ok", "TXT": "unknown",
                       "SOA": "unknown", "CNAME": "nodata"},
    "email_auth": {
        "spf": {"present": False, "records": [], "policy": None, "status": "unknown"},
        "dmarc": {"present": False, "records": [], "status": "nxdomain"},
        "dkim": {"selectors_found": ["google"], "selectors_tested": 18,
                 "records": {"google": ['"v=DKIM1; k=rsa; p=KEY1"']}, "selectors_unknown": ["selector1", "k1"]},
        "bimi": {"present": False, "records": [], "status": "unknown"},
        "caa": {"present": False, "records": [], "status": "unknown"},
    },
    "subdomains": {"tested": 25,
                   "active": [{"fqdn": _sub("www"), "A": ["192.0.2.20"], "CNAME": []},
                              {"fqdn": _sub("autodiscover"), "A": [], "CNAME": ["autodiscover.provider.example"]}],
                   "unknown": [_sub("mail"), _sub("webmail")]},
    "error": None,
}


def _without_timestamp(body):
    return {k: v for k, v in body.items() if k != "timestamp"}


def _key_order(node):
    """L'ordine delle chiavi di ogni dict, ricorsivo: la forma del JSON scritto negli snapshot."""
    if isinstance(node, dict):
        return [(k, _key_order(v)) for k, v in node.items()]
    if isinstance(node, list):
        return [_key_order(v) for v in node]
    return None


def _expected_argv(path):
    """Le query del codice senza scadenza per `path`: argv senza "dig", una per query, in ordine."""
    names = [(DOMAIN, t) for t in _BASE]
    if path in ("full", "full+sub"):
        names += [(f"_dmarc.{DOMAIN}", "TXT")] + [(_dkim(s), "TXT") for s in DEFAULT_DKIM_SELECTORS]
        names += [(f"default._bimi.{DOMAIN}", "TXT"), (DOMAIN, "CAA")]
    if path == "full+sub":
        names += [(_sub(s), t) for s in DEFAULT_SUBDOMAINS for t in ("A", "CNAME")]
    return sorted([*_DIG_OPTIONS, n, t] for n, t in names)


_UNKNOWN_SECTION = {"present": False, "records": [], "status": "unknown"}
_UNKNOWN_SPF = {"present": False, "records": [], "policy": None, "status": "unknown"}


def _cut(healthy, *, base=(), sections=(), selectors=(), subdomains=()):
    """La risposta `healthy` con le parti indicate nella forma che il ramo `unknown` dà a una query senza esito
    (vedi `TestCutPartsUseTheExistingUnknownShape`): record `[]` e stato `unknown`, SPF come il suo TXT, sezione
    con `present: false`, selettore in `selectors_unknown`, sottodominio in `unknown`; `error` se i 7 tipi base
    sono tutti senza esito."""
    out = copy.deepcopy(healthy)
    for rtype in base:
        out["records"][rtype] = []
        out["records_status"][rtype] = "unknown"
    if all(out["records_status"][t] == "unknown" for t in _BASE):
        out["error"] = dns_intel.DNS_ALL_UNKNOWN_ERROR
    email = out["email_auth"]
    if "TXT" in base and email:
        email["spf"] = dict(_UNKNOWN_SPF)
    for section in sections:
        email[section] = dict(_UNKNOWN_SECTION)
    if selectors:
        dkim = email["dkim"]
        dkim["selectors_found"] = [s for s in dkim["selectors_found"] if s not in selectors]
        dkim["records"] = {s: r for s, r in dkim["records"].items() if s not in selectors}
        dkim["selectors_unknown"] = [s for s in DEFAULT_DKIM_SELECTORS
                                     if s in selectors or s in dkim["selectors_unknown"]]
    if subdomains:
        subs = out["subdomains"]
        subs["active"] = [a for a in subs["active"] if a["fqdn"] not in subdomains]
        subs["unknown"] = [_sub(s) for s in DEFAULT_SUBDOMAINS if _sub(s) in subdomains or _sub(s) in subs["unknown"]]
    return out


_ALL_SUBDOMAINS = tuple(_sub(s) for s in DEFAULT_SUBDOMAINS)


def _wrong_parts(body, healthy):
    """Le parti di `body` che non sono né il valore vero (`healthy`) né la forma `unknown`: un record sparito, un
    `nodata` inventato, una sezione omessa. Vuoto per una risposta completa o tagliata correttamente."""
    wrong = []
    if set(body) != set(healthy) | {"timestamp"}:
        return [("chiavi", sorted(body))]
    for rtype in _BASE:
        got = (body["records"].get(rtype, "<omesso>"), body["records_status"].get(rtype, "<omesso>"))
        if got not in ((healthy["records"][rtype], healthy["records_status"][rtype]), ([], "unknown")):
            wrong.append((rtype, got))
    email, true_email = body["email_auth"], healthy["email_auth"]
    if set(email) != set(true_email):
        wrong.append(("email_auth", sorted(email)))
        return wrong
    for section, unknown in [("spf", _UNKNOWN_SPF)] + [(s, _UNKNOWN_SECTION) for s in _SECTIONS]:
        if section in email and email[section] not in (true_email[section], unknown):
            wrong.append((section, email[section]))
    if "dkim" in email:
        dkim, true_dkim = email["dkim"], true_email["dkim"]
        for sel in DEFAULT_DKIM_SELECTORS:
            got = (sel in dkim["selectors_found"], dkim["records"].get(sel), sel in dkim["selectors_unknown"])
            true = (sel in true_dkim["selectors_found"], true_dkim["records"].get(sel), False)
            if got not in (true, (False, None, True)):
                wrong.append((f"dkim:{sel}", got))
        if dkim["selectors_tested"] != true_dkim["selectors_tested"]:
            wrong.append(("dkim:selectors_tested", dkim["selectors_tested"]))
    subs, true_subs = body["subdomains"], healthy["subdomains"]
    if true_subs:
        active = {a["fqdn"]: a for a in subs.get("active", [])}
        true_active = {a["fqdn"]: a for a in true_subs["active"]}
        for fqdn in _ALL_SUBDOMAINS:
            got = (active.get(fqdn), fqdn in subs.get("unknown", []))
            if got not in ((true_active.get(fqdn), False), (None, True)):
                wrong.append((fqdn, got))
        if subs.get("tested") != true_subs["tested"]:
            wrong.append(("subdomains:tested", subs.get("tested")))
    return wrong


# ── 0. La costante ───────────────────────────────────────────────────────────────────────────────────────────

class TestDeadlineConstant:

    def test_default_deadline_is_40_seconds_below_the_orchestrator_timeout(self):
        from services import orchestrator

        assert dns_intel.DNS_DEADLINE_S == 40
        # La risposta deve arrivare prima che l'orchestrator rinunci (45 s), con margine.
        assert dns_intel.DNS_DEADLINE_S < orchestrator.TIMEOUT


# ── 1. Resolver muto ─────────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="class")
def silent_run(tmp_path_factory):
    with _installed_fake(tmp_path_factory.mktemp("sec29-silent")) as (fake, mp):
        fake.configure(_ZONE, hang=[("*", "*")])
        return _request(fake, mp, _params("full+sub"), _DEADLINE_S)


class TestSilentResolver:
    """Nessuna query riceve risposta: la richiesta dell'orchestrator (`full=true&subdomains=true`) deve chiudersi
    alla scadenza con ogni parte `unknown`, senza lasciare processi né thread."""

    def test_full_request_answers_within_the_deadline(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.elapsed <= _DEADLINE_S + _MARGIN_S

    def test_no_dig_survives_the_response(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.digs_at_response == [], "dig ancora vivi alla risposta"
        assert silent_run.digs_after == [], f"dig ancora vivi {_SETTLE_S} s dopo la risposta"

    def test_no_worker_thread_survives_the_response(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.threads_after == []

    def test_every_part_is_unknown_in_the_existing_shape(self, silent_run):
        body = silent_run.must_have_answered()

        expected = _cut(_HEALTHY["full+sub"], base=_BASE, sections=_SECTIONS, selectors=DEFAULT_DKIM_SELECTORS,
                        subdomains=_ALL_SUBDOMAINS)
        assert _without_timestamp(body) == expected

    def test_no_query_starts_after_the_deadline(self, silent_run):
        silent_run.must_have_answered()

        late = [(round(t, 3), argv[-2:]) for t, argv in silent_run.spawns if t >= _DEADLINE_S]
        assert late == [], f"{len(late)} dig avviati dopo la scadenza, primi: {late[:3]}"

    def test_every_dig_keeps_the_integer_time_and_tries(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.spawns, "nessun dig avviato"
        options = {tuple(argv[:-2]) for _, argv in silent_run.spawns}
        assert options == {tuple(_DIG_OPTIONS)}

    def test_never_more_than_ten_digs_at_once(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.peak <= _MAX_DIGS, f"picco di dig contemporanei: {silent_run.peak}"

    def test_answer_comes_within_one_second_of_the_deadline(self, silent_run):
        silent_run.must_have_answered()

        assert silent_run.elapsed <= _DEADLINE_S + _TIGHT_MARGIN_S, (
            f"risposta a {silent_run.elapsed:.2f} s con scadenza {_DEADLINE_S} s")

    def test_all_seven_base_types_start_together(self, silent_run):
        # Con i 7 tipi base muti partono tutti e 7 subito: un pool più piccolo ne lascerebbe alcuni ad aspettare la
        # scadenza, che li trova non partiti, e con meno tipi muti farebbe attendere fino a 20 s quelli che rispondono.
        silent_run.must_have_answered()

        started = {argv[-1]: round(t, 2) for t, argv in silent_run.spawns if argv[-2] == DOMAIN and argv[-1] in _BASE}
        assert sorted(started) == sorted(_BASE), f"tipi base avviati: {started}"
        assert max(started.values()) < _DEADLINE_S / 2, f"tipi base avviati tardi: {started}"
        assert silent_run.peak >= len(_BASE), f"picco di dig contemporanei: {silent_run.peak}"


# ── 2-bis. Una query muta che parte tardi ────────────────────────────────────────────────────────────────────

_LATE_DEADLINE_S = 4.0
# Il DMARC risponde dopo 1,5 s, quindi il BIMI muto parte dopo 1,5 s per costruzione (~1,7 s senza carico, ~3 s con
# la CPU tre volte sovrascritta): un `dig` limitato alla scadenza intera dal proprio avvio risponderebbe almeno a
# 4 + 1,5 s, oltre il margine di 1 s; partendo entro ~3 s resta comunque prima della scadenza.
_LATE_DMARC_DELAY_S = 1.5


@pytest.fixture(scope="class", params=[10, 1], ids=["timeout-10", "timeout-1"])
def late_run(request, tmp_path_factory):
    # `DNS_TIMEOUT` 10: il tempo residuo del BIMI (~2,3 s) è sotto `timeout`. `DNS_TIMEOUT` 1 (tetto per query 11 s):
    # il residuo è sopra `timeout` e sotto il tetto, come in produzione per gran parte dei 40 s (`timeout` 10).
    with _installed_fake(tmp_path_factory.mktemp(f"sec29-late-{request.param}")) as (fake, mp):
        mp.setattr(dns_intel, "DNS_TIMEOUT", request.param)
        fake.configure(_ZONE, hang=[(f"default._bimi.{DOMAIN}", "TXT")],
                       delays={(f"_dmarc.{DOMAIN}", "TXT"): _LATE_DMARC_DELAY_S})
        out = _request(fake, mp, _params("full+sub"), _LATE_DEADLINE_S)
    out.bimi_started = [t for t, argv in out.spawns if argv[-2:] == [f"default._bimi.{DOMAIN}", "TXT"]]
    return out


class TestSilentQueryStartingLate:
    """Il DMARC risponde lento ma in tempo, DKIM subito, poi il BIMI resta muto: parte a ~1,7 s di una scadenza di 4 s.
    Deve essere ucciso alla scadenza della richiesta, non dopo una scadenza intera o il tetto per query contati dal
    suo avvio. Le query mute degli altri test partono tutte nei primi decimi di secondo, quando il tempo residuo è
    ancora quasi l'intera scadenza, e non distinguono «tempo residuo» da «scadenza intera per ogni query»."""

    def test_silent_query_started_late_is_cut_at_the_request_deadline(self, late_run):
        late_run.must_have_answered()

        assert late_run.bimi_started, "il BIMI muto non è partito"
        start = late_run.bimi_started[0]
        # Precondizione: il BIMI parte tardi (oltre lo sforo ammesso) e prima della scadenza.
        assert _LATE_DMARC_DELAY_S <= start < _LATE_DEADLINE_S, f"BIMI avviato a {start:.2f} s"
        assert late_run.elapsed <= _LATE_DEADLINE_S + _TIGHT_MARGIN_S, (
            f"BIMI avviato a {start:.2f} s, risposta a {late_run.elapsed:.2f} s con scadenza {_LATE_DEADLINE_S} s")

    def test_parts_answered_before_the_late_query_are_kept(self, late_run):
        body = late_run.must_have_answered()

        expected = _cut(_HEALTHY["full+sub"], sections=["bimi", "caa"], subdomains=_ALL_SUBDOMAINS)
        assert _without_timestamp(body) == expected

    def test_no_dig_survives_the_response(self, late_run):
        late_run.must_have_answered()

        assert late_run.digs_at_response == [] and late_run.digs_after == []


# ── 2. Risultato parziale ────────────────────────────────────────────────────────────────────────────────────

class _Partial:
    def __init__(self, hang, cut, known, deadline=_DEADLINE_S):
        self.hang = hang          # [(nome, tipo)] muti
        self.cut = cut            # parti che alla scadenza devono essere `unknown` (argomenti di `_cut`)
        self.known = known        # parti risposte in tempo: devono essere il valore vero (vedi `_known_view`)
        self.deadline = deadline  # le parti `known` rispondono in circa 0,1-0,6 s senza carico


_PARTIALS = {
    # Due tipi base muti: lo stadio base dura fino alla scadenza, gli stadi dopo non partono.
    "base-AAAA-TXT": _Partial(
        [(DOMAIN, "AAAA"), (DOMAIN, "TXT")],
        {"base": ["AAAA", "TXT"], "sections": _SECTIONS, "selectors": DEFAULT_DKIM_SELECTORS,
         "subdomains": _ALL_SUBDOMAINS},
        {"base": ["A", "MX", "NS", "SOA", "CNAME"]}),
    # Tre selettori DKIM muti: gli altri 15 rispondono, BIMI, CAA e sottodomini non partono.
    "dkim-three": _Partial(
        [(_dkim("default"), "TXT"), (_dkim("k1"), "TXT"), (_dkim("s2"), "TXT")],
        {"sections": ["bimi", "caa"], "selectors": ["default", "k1", "s2"], "subdomains": _ALL_SUBDOMAINS},
        {"base": _BASE, "sections": ["spf", "dmarc"],
         "selectors": [s for s in DEFAULT_DKIM_SELECTORS if s not in ("default", "k1", "s2")]}),
    # L'A di un sottodominio muto: tutto il resto risponde (76 query prima della scadenza: margine più ampio).
    "subdomain-mail": _Partial(
        [(_sub("mail"), "A")],
        {"subdomains": [_sub("mail")]},
        {"base": _BASE, "sections": ["spf", *_SECTIONS], "selectors": DEFAULT_DKIM_SELECTORS,
         "subdomains": [f for f in _ALL_SUBDOMAINS if f != _sub("mail")]},
        deadline=3.0),
}


def _known_view(body, known):
    """Le parti `known` di `body`, per il confronto con la stessa vista della risposta sana."""
    view = {}
    for rtype in known.get("base", ()):
        view[rtype] = (body["records"].get(rtype), body["records_status"].get(rtype))
    email = body.get("email_auth", {})
    for section in known.get("sections", ()):
        view[section] = email.get(section)
    dkim = email.get("dkim", {})
    for sel in known.get("selectors", ()):
        view[f"dkim:{sel}"] = (sel in dkim.get("selectors_found", []), dkim.get("records", {}).get(sel),
                               sel in dkim.get("selectors_unknown", []))
    subs = body.get("subdomains", {})
    for fqdn in known.get("subdomains", ()):
        view[fqdn] = ([a for a in subs.get("active", []) if a["fqdn"] == fqdn], fqdn in subs.get("unknown", []))
    return view


@pytest.fixture(scope="class", params=list(_PARTIALS), ids=list(_PARTIALS))
def partial_run(request, tmp_path_factory):
    spec = _PARTIALS[request.param]
    with _installed_fake(tmp_path_factory.mktemp(f"sec29-partial-{request.param}")) as (fake, mp):
        fake.configure(_ZONE, hang=spec.hang)
        out = _request(fake, mp, _params("full+sub"), spec.deadline)
    out.spec = spec
    return out


class TestPartialResult:
    """Alcuni nomi e tipi rispondono subito, altri restano muti: alla scadenza ciò che ha risposto è nella risposta
    con il suo valore, ciò che è muto o non è partito è `unknown`, e nessuna parte manca o diventa «assente»."""

    def test_answers_within_the_deadline(self, partial_run):
        partial_run.must_have_answered()

        assert partial_run.elapsed <= partial_run.deadline + _MARGIN_S

    def test_parts_answered_in_time_carry_their_answer(self, partial_run):
        body = partial_run.must_have_answered()

        known = partial_run.spec.known
        assert _known_view(body, known) == _known_view(_HEALTHY["full+sub"], known)
        assert body["error"] is None

    def test_parts_cut_by_the_deadline_are_unknown(self, partial_run):
        body = partial_run.must_have_answered()

        assert _without_timestamp(body) == _cut(_HEALTHY["full+sub"], **partial_run.spec.cut)

    def test_no_part_is_omitted_or_reported_absent(self, partial_run):
        body = partial_run.must_have_answered()

        assert _wrong_parts(body, _HEALTHY["full+sub"]) == []

    def test_no_dig_survives_the_response(self, partial_run):
        partial_run.must_have_answered()

        assert partial_run.digs_at_response == [] and partial_run.digs_after == []


class TestCutPartsUseTheExistingUnknownShape:
    """Controllo di `_cut` (verde anche senza la scadenza): la forma attesa per una parte tagliata dalla scadenza è
    quella che `/dns` dà alla stessa query quando risponde subito con SERVFAIL."""

    @pytest.mark.parametrize("name", list(_PARTIALS))
    def test_cut_shape_is_what_a_fast_servfail_produces(self, tmp_path, name):
        spec = _PARTIALS[name]
        zone = dict(_ZONE)
        for key in spec.hang:
            zone[key] = _SERVFAIL
        # Nessuna query è muta: anche le parti che la scadenza non raggiungerebbe falliscono subito, così la
        # risposta descrive esattamente il taglio atteso.
        cut = spec.cut
        for rtype in cut.get("base", ()):
            zone[(DOMAIN, rtype)] = _SERVFAIL
        for section in cut.get("sections", ()):
            zone[{"dmarc": (f"_dmarc.{DOMAIN}", "TXT"), "bimi": (f"default._bimi.{DOMAIN}", "TXT"),
                  "caa": (DOMAIN, "CAA")}[section]] = _SERVFAIL
        for sel in cut.get("selectors", ()):
            zone[(_dkim(sel), "TXT")] = _SERVFAIL
        for fqdn in cut.get("subdomains", ()):
            zone[(fqdn, "A")] = zone[(fqdn, "CNAME")] = _SERVFAIL
        with _installed_fake(tmp_path) as (fake, mp):
            fake.configure(zone)
            out = _request(fake, mp, _params("full+sub"), 60.0, bound=60.0)

        assert _without_timestamp(out.must_have_answered()) == _cut(_HEALTHY["full+sub"], **cut)


# ── 3. DNS che risponde: risposta invariata ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="class", params=["base", "full", "full+sub"])
def healthy_run(request, tmp_path_factory):
    with _installed_fake(tmp_path_factory.mktemp("sec29-healthy")) as (fake, mp):
        fake.configure(_ZONE)
        out = _request(fake, mp, _params(request.param), 40)
    out.path = request.param
    return out


class TestHealthyDnsUnchanged:
    """Con un DNS che risponde subito la scadenza non deve cambiare nulla: stesso corpo, stesso ordine delle chiavi,
    stesse query con lo stesso argv. Verdi anche senza la scadenza: sono la rete contro una regressione."""

    def test_body_is_unchanged(self, healthy_run):
        assert _without_timestamp(healthy_run.must_have_answered()) == _HEALTHY[healthy_run.path]

    def test_key_order_is_unchanged(self, healthy_run):
        body = _without_timestamp(healthy_run.must_have_answered())

        assert _key_order(body) == _key_order(_HEALTHY[healthy_run.path])

    def test_queries_and_argv_are_unchanged(self, healthy_run):
        healthy_run.must_have_answered()

        assert sorted(argv for _, argv in healthy_run.spawns) == _expected_argv(healthy_run.path)

    def test_fast_negative_and_failed_answers_are_unchanged(self, tmp_path):
        with _installed_fake(tmp_path) as (fake, mp):
            fake.configure(_ZONE_FAST_FAILURES)
            out = _request(fake, mp, _params("full+sub"), 40)

        assert _without_timestamp(out.must_have_answered()) == _FAST_FAILURES_BODY


# ── 4. I tipi base in parallelo, al più 10 `dig` insieme ─────────────────────────────────────────────────────

class TestBaseTypesInParallel:

    @pytest.fixture
    def fake(self, tmp_path):
        with _installed_fake(tmp_path) as installed:
            yield installed

    def test_two_silent_base_types_do_not_cost_the_others(self, fake):
        # A e AAAA muti, il resto subito: in serie la scadenza se ne andrebbe tutta nei primi due tipi.
        dig, mp = fake
        silent = ["A", "AAAA"]
        dig.configure(_ZONE, hang=[(DOMAIN, t) for t in silent])

        out = _request(dig, mp, _params("base"), _DEADLINE_S)

        body = out.must_have_answered()
        others = [t for t in _BASE if t not in silent]
        assert {t: (body["records"][t], body["records_status"][t]) for t in others} == \
            {t: (_HEALTHY_BASE["records"][t], _HEALTHY_BASE["records_status"][t]) for t in others}
        assert {t: body["records_status"][t] for t in silent} == {t: "unknown" for t in silent}
        assert body["error"] is None

    def test_base_types_take_one_query_time_not_their_sum(self, fake):
        dig, mp = fake
        delay = 1.0                                     # in serie: 7 x 1 = 7 s
        dig.configure(_ZONE, delay=delay)

        out = _request(dig, mp, _params("base"), 40, bound=7 * delay + _MARGIN_S)

        assert _without_timestamp(out.must_have_answered()) == _HEALTHY_BASE
        assert out.elapsed < 2 * delay + 1.0, f"7 tipi base in {out.elapsed:.2f} s con {delay} s a query"

    def test_never_more_than_ten_digs_at_once(self, fake):
        # Ogni risposta arriva dopo 0,15 s: ogni stadio riempie il proprio pool. Verde anche senza la scadenza (picco 10).
        dig, mp = fake
        dig.configure(_ZONE, delay=0.15)

        out = _request(dig, mp, _params("full+sub"), 40, bound=60)

        assert _without_timestamp(out.must_have_answered()) == _HEALTHY["full+sub"]
        assert 7 <= out.peak <= _MAX_DIGS, f"picco di dig contemporanei: {out.peak}"


# ── 5. `dig_lookup` con un limite complessivo ────────────────────────────────────────────────────────────────

class TestDigLookupLimit:
    """`dig_lookup(fqdn, rtype, timeout, *, limit=...)`: `limit` è il tempo massimo dell'intera chiamata."""

    @pytest.fixture
    def fake(self, tmp_path):
        with _installed_fake(tmp_path) as installed:
            yield installed[0]

    def _lookup(self, fake, *args, **kwargs):
        fake.unrelease()
        fake.reset()
        t0 = time.monotonic()
        result = utils.dig_lookup(*args, **kwargs)
        return result, time.monotonic() - t0

    def test_hung_dig_is_killed_at_the_limit(self, fake):
        fake.configure(_ZONE, hang=[("*", "*")])

        result, elapsed = self._lookup(fake, DOMAIN, "A", 10, limit=1.0)

        alive = fake.alive()
        assert result == ("unknown", [])
        assert 0.9 <= elapsed <= 1.0 + _MARGIN_S / 2, f"dig_lookup è durato {elapsed:.2f} s con limit=1.0"
        assert alive == [], "il dig muto è ancora vivo dopo il ritorno"

    @pytest.mark.parametrize("limit", [0.4, 1.5, 2.7, 7.25, 25.0])
    def test_limit_leaves_integer_time_and_tries_unchanged(self, fake, limit):
        fake.configure(_ZONE)

        result, _ = self._lookup(fake, DOMAIN, "A", 10, limit=limit)

        assert [argv[1:] for _, argv in fake.spawns] == [[*_DIG_OPTIONS, DOMAIN, "A"]]
        assert result == ("ok", ["192.0.2.10", "192.0.2.11"])

    @pytest.mark.parametrize("timeout, limit", [(3, 1.5), (1, 0.75), (10, 9.99)])
    def test_fractional_remaining_time_never_reaches_dig(self, fake, timeout, limit):
        # `dig` accetta solo `+time` interi: con `+time=1.5` esce con 10 senza interrogare nulla.
        fake.configure(_ZONE)

        result, _ = self._lookup(fake, DOMAIN, "MX", timeout, limit=limit)

        (argv,) = [argv for _, argv in fake.spawns]
        assert f"+time={timeout}" in argv and "+tries=2" in argv
        assert result == ("ok", [f"10 mail.{DOMAIN}"])

    def test_hung_dig_with_time_left_above_its_timeout_is_killed_at_the_limit(self, fake):
        # `timeout` 1 (tetto per query 11 s), `limit` 2: vale il tempo residuo anche se è più lungo di `timeout`.
        fake.configure(_ZONE, hang=[("*", "*")])

        result, elapsed = self._lookup(fake, DOMAIN, "A", 1, limit=2.0)

        alive = fake.alive()
        assert result == ("unknown", [])
        assert 1.9 <= elapsed <= 2.0 + _TIGHT_MARGIN_S, f"dig_lookup è durato {elapsed:.2f} s con limit=2.0"
        assert alive == [], "il dig muto è ancora vivo dopo il ritorno"

    @pytest.mark.parametrize("timeout, limit, expected", [
        pytest.param(10, 2.5, 2.5, id="remaining-below-timeout"),
        pytest.param(1, 5.0, 5.0, id="remaining-between-timeout-and-cap"),
        pytest.param(3, 12.75, 12.75, id="remaining-just-below-cap"),
        pytest.param(3, 13.25, 13, id="remaining-just-above-cap"),
        pytest.param(1, 30.0, 11, id="remaining-far-above-cap"),
        pytest.param(10, 40.0, 20, id="production-start-of-request"),
    ])
    def test_process_lives_at_most_the_smaller_of_cap_and_remaining_time(self, fake, timeout, limit, expected):
        # Il limite di tempo dato a `subprocess.run` è `min(timeout + 10, limit)`: il tetto per query di sempre quando
        # il tempo residuo è lungo, il tempo residuo quando è più corto.
        fake.configure(_ZONE)
        seen = []
        real_run = subprocess.run

        def spy(*args, **kwargs):
            seen.append(kwargs.get("timeout"))
            return real_run(*args, **kwargs)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "run", spy)
            result, _ = self._lookup(fake, DOMAIN, "A", timeout, limit=limit)

        assert seen == [expected]
        assert result == ("ok", ["192.0.2.10", "192.0.2.11"])

    @pytest.mark.parametrize("limit", [0, 0.0, -1.0])
    def test_no_dig_starts_without_time_left(self, fake, limit):
        fake.configure(_ZONE)

        result, _ = self._lookup(fake, DOMAIN, "A", 10, limit=limit)

        assert result == ("unknown", [])
        assert fake.spawns == []

    def test_answer_within_the_limit_is_the_same_as_without_limit(self, fake):
        fake.configure(_ZONE)

        with_limit, _ = self._lookup(fake, DOMAIN, "TXT", 10, limit=5.0)
        without, _ = self._lookup(fake, DOMAIN, "TXT", 10)

        assert with_limit == without == ("ok", ['"hello world"', '"v=spf1 -all"'])


# ── 6. A valle: orchestrator, intel store, classificatore ────────────────────────────────────────────────────

_CLIENT = "tenant-sec29"
_FEED_ENTRY = {"domain": DOMAIN, "client": _CLIENT, "type": "target", "legitimate": "shop.example",
               "fuzzer": "insertion"}
_CERT = {"domain": DOMAIN, "timestamp": "2026-10-24T10:00:00Z",
         "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
         "tls_live": None, "san_subdomains_discovered": [], "error": None}
_HTTP = {"domain": DOMAIN, "timestamp": "2026-10-24T10:00:00Z", "checks": [], "overall_status": "down",
         "hidden_elements_risk": 0, "error": None}
_ORCH_MARGIN_S = 5.0          # come in produzione: l'orchestrator aspetta 45 s, la scadenza è 40 s


class _Resp:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload, self.ok, self.status_code = payload, ok, status_code

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _Cycle:
    def __init__(self, event, alerts, snapshot_dns):
        self.event = event
        self.alerts = alerts
        self.dns = snapshot_dns


def _run_chain(root):
    """Tre cicli di `_run_pipeline` su `_ZONE`: sano, con AAAA e TXT muti (scadenza `_DEADLINE_S`), sano. L'orchestrator
    aspetta `/dns` al più scadenza + 5 s, come in produzione (40 s e 45 s). I cicli sani hanno una scadenza ampia."""
    import services.orchestrator as o
    from services.classifier import app as classifier_app

    cycles = []
    with _installed_fake(root / "dns") as (fake, mp):
        mp.setattr(o, "INTEL_STORE", True)
        mp.setattr(o, "CASE_INGEST", False)
        mp.setattr(o.intel_store, "SNAP_DIR", root / "snapshots")
        mp.setattr(o.intel_store, "HIST_DIR", root / "history")
        mp.setattr(o, "TIMEOUT", _DEADLINE_S + _ORCH_MARGIN_S)
        dns_client = TestClient(dns_intel.app)
        cls_client = TestClient(classifier_app, raise_server_exceptions=False)
        published = []
        abandoned = []

        def _dns_get(path, timeout):
            box = {}

            def call():
                try:
                    box["r"] = dns_client.get(path)
                except BaseException as exc:      # come un errore di trasporto
                    box["error"] = exc
            th = threading.Thread(target=call, name="sec29-orchestrator-dns", daemon=True)
            _LIVE_THREADS.append(th)
            th.start()
            th.join(timeout)
            if th.is_alive():
                abandoned.append(th)
                raise TimeoutError(f"read timeout={timeout}")
            if "error" in box:
                raise box["error"]
            r = box["r"]
            return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _Resp({"domains": [_FEED_ENTRY]})
            if "/feed/whitelist" in url:
                return _Resp({"whitelist": {}})
            if url.startswith(o.DNS_URL):
                return _dns_get(url[len(o.DNS_URL):], timeout)
            if url.startswith(o.CERT_URL):
                return _Resp(_CERT)
            if url.startswith(o.HTTP_URL):
                return _Resp(_HTTP)
            raise AssertionError(f"GET non atteso: {url}")

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
                return _Resp({})
            if url.startswith(o.CLASSIFY_URL):
                r = cls_client.post(url[len(o.CLASSIFY_URL):], json=json)
                return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)
            raise AssertionError(f"POST non atteso: {url}")

        mp.setattr(o._session, "get", _get)
        mp.setattr(o._session, "post", _post)

        for hang, deadline in [((), 40), ([(DOMAIN, "AAAA"), (DOMAIN, "TXT")], _DEADLINE_S), ((), 40)]:
            fake.unrelease()
            fake.reset()
            fake.configure(_ZONE, hang=hang)
            mp.setattr(dns_intel, "DNS_DEADLINE_S", deadline, raising=False)
            before = len(o.intel_store.load_history(_CLIENT, DOMAIN, limit=1000))
            published.clear()
            o._run_pipeline(o.TriggerRequest(client=_CLIENT, include_whois=False, include_reputation=False,
                                             include_dnstwist=False, variant_intel=False, scope="all"))
            if abandoned:
                # La richiesta /dns abbandonata dall'orchestrator finisce prima del ciclo seguente.
                fake.release()
                for th in abandoned:
                    th.join(_RELEASE_JOIN_S)
                abandoned.clear()
            assert o._progress["phase"] != "error", "la pipeline è terminata con un errore"
            history = o.intel_store.load_history(_CLIENT, DOMAIN, limit=1000)
            new = history[:len(history) - before]
            snapshot = (o.intel_store.load_snapshot(_CLIENT, DOMAIN) or {}).get("intel", {}).get("dns")
            event = next(e for e in published if e["domain"] == DOMAIN)
            cycles.append(_Cycle(event, [(a["type"], a.get("message", "")) for e in new for a in e["alerts"]],
                                 snapshot))
    return cycles


@pytest.fixture(scope="class")
def chain(tmp_path_factory):
    return _run_chain(tmp_path_factory.mktemp("sec29-chain"))


_FRESH = ["A", "MX", "NS", "SOA", "CNAME"]              # risposti prima della scadenza nel ciclo con AAAA e TXT muti
_CARRIED = ["AAAA", "TXT", "spf", "dmarc", "bimi", "caa"]   # muti o non raggiunti: riportati dal ciclo prima


def _part(dns, part):
    if part in _BASE:
        return dns["records"][part], dns["records_status"][part]
    return dns["email_auth"][part]


class TestDownstreamOfAPartialResult:
    """sano -> parziale (AAAA e TXT muti) -> sano lungo la catena vera: `/dns`, `_run_pipeline`, intel store,
    `/classify/variant` e `/diff` del classificatore. Il parziale è un'osservazione: ciò che ha risposto è fresco nello
    snapshot e decide la classificazione, ciò che è `unknown` si riporta dal ciclo prima, e nessun ciclo allerta."""

    def test_partial_result_reaches_the_orchestrator(self, chain):
        summary = chain[1].event["intel_summary"]

        assert (summary["dns_a_status"], summary["dns_mx_status"]) == ("ok", "ok"), summary

    def test_no_cycle_produces_an_alert(self, chain):
        assert [c.alerts for c in chain] == [[], [], []]

    def test_parts_answered_before_the_deadline_are_fresh_in_the_snapshot(self, chain):
        healthy, partial = chain[0].dns, chain[1].dns

        assert {p: _part(partial, p) for p in _FRESH} == {p: _part(healthy, p) for p in _FRESH}
        carried = sorted((partial.get("carried_over") or {}).keys())
        assert [p for p in _FRESH if p in carried] == [], f"riportate come vecchie: {carried}"

    def test_parts_cut_by_the_deadline_keep_the_previous_observation(self, chain):
        healthy, partial = chain[0].dns, chain[1].dns

        assert {p: _part(partial, p) for p in _CARRIED} == {p: _part(healthy, p) for p in _CARRIED}
        assert sorted(p for p in (partial.get("carried_over") or {}) if p in _CARRIED) == sorted(_CARRIED)

    def test_partial_cycle_is_classified_from_what_was_observed(self, chain):
        healthy, partial = (c.event["classification"]["auto_classification"] for c in chain[:2])

        assert partial == healthy != "insufficient_data"


# ── 7. Una scadenza per richiesta, letta a ogni chiamata ─────────────────────────────────────────────────────

class TestDeadlinePerRequest:

    @pytest.fixture
    def fake(self, tmp_path):
        with _installed_fake(tmp_path) as installed:
            installed[0].configure(_ZONE, hang=[("*", "*")])
            yield installed

    def test_deadline_is_read_on_each_call(self, fake):
        # Due richieste mute di fila con 0,5 s e 2,5 s: la durata segue il valore della chiamata, non quello
        # letto all'import o alla prima richiesta del processo.
        dig, mp = fake

        first = _request(dig, mp, _params("base"), 0.5)
        second = _request(dig, mp, _params("base"), 2.5)

        first.must_have_answered()
        second.must_have_answered()
        assert 0.5 <= first.elapsed <= 0.5 + _MARGIN_S
        assert 2.5 <= second.elapsed <= 2.5 + _MARGIN_S
        assert second.elapsed - first.elapsed >= 1.0, (
            f"0,5 s -> {first.elapsed:.2f} s, 2,5 s -> {second.elapsed:.2f} s: la scadenza non segue la costante")

    def test_each_request_keeps_the_deadline_it_started_with(self, fake):
        # R1 (`full=true`, 2,5 s): tipi base e DMARC rispondono dopo 0,6 s, i selettori DKIM sono muti. 0,3 s dopo la
        # costante passa a 0,7 s e parte R2, su un altro dominio tutto muto. R1 deve chiudersi alla propria scadenza
        # con il DMARC ottenuto: una scadenza condivisa fra le richieste la accorcerebbe (DMARC tagliato, risposta
        # a 1 s) o la toglierebbe alla fine di R2 (selettori fino a 20 s).
        dig, mp = fake
        dig.unrelease()
        dig.reset()
        dig.configure(_ZONE, hang=[(_OTHER_DOMAIN, "*")] + [(_dkim(s), "TXT") for s in DEFAULT_DKIM_SELECTORS],
                      delay=0.6)
        boxes = [{}, {}]
        mp.setattr(dns_intel, "DNS_DEADLINE_S", 2.5, raising=False)
        t0 = time.monotonic()
        first = _start(TestClient(dns_intel.app), {"domain": DOMAIN, "full": "true"}, boxes[0])
        time.sleep(0.3)
        mp.setattr(dns_intel, "DNS_DEADLINE_S", 0.7, raising=False)
        t1 = time.monotonic()
        second = _start(TestClient(dns_intel.app), {"domain": _OTHER_DOMAIN}, boxes[1])
        first.join(2.5 + _MARGIN_S)
        second.join(max(0.0, t1 + 0.7 + _MARGIN_S - time.monotonic()))
        answered = [not first.is_alive(), not second.is_alive()]
        dig.release()

        assert answered == [True, True], "una delle due richieste non ha risposto entro scadenza + margine"
        assert [b["response"].status_code for b in boxes] == [200, 200]
        elapsed = [boxes[0]["t"] - t0, boxes[1]["t"] - t1]
        assert 0.7 <= elapsed[1] <= 0.7 + _MARGIN_S, f"R2: {elapsed[1]:.2f} s"
        assert 2.5 <= elapsed[0] <= 2.5 + _MARGIN_S, f"R1: {elapsed[0]:.2f} s invece di 2,5 s"
        assert boxes[0]["response"].json()["email_auth"]["dmarc"]["status"] == "ok"
