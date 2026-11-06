"""Shared test fixtures."""

import pytest

# BUILD-06 — costo PBKDF2 ridotto NEL SOLO processo di test.
#
# A 600.000 iterazioni ogni hash costa circa un quinto di secondo, e la suite ne
# calcola molti: ogni login e ogni utente creato nei test del case-manager, più
# l'admin che `init_db()` crea per ciascuno scenario di test_col02_chain.py. Era
# la singola voce più pesante del tempo della suite, e nessun test preesistente
# verifica il NUMERO di iterazioni: verificano che hash e verifica siano coerenti
# fra loro.
#
# Perché qui, a livello di modulo, e non in una fixture: l'admin di
# `services.case_manager` viene creato all'IMPORT di tests/test_case_manager.py,
# cioè in fase di raccolta, prima di qualunque fixture (anche di sessione). Con
# una fixture il costo ridotto arriverebbe tardi: hash creato a 600.000
# iterazioni, verificato a 1.000, e i login falliscono. Questo file è caricato
# prima dei moduli di test che gli stanno accanto.
#
# Perché NON una variabile d'ambiente letta da `shared/auth.py`: significherebbe
# un interruttore nel codice servito che abbassa l'hashing delle password, e basta
# un valore sbagliato nell'ambiente del container per indebolirlo in silenzio.
# L'override vive in `tests/`, che non entra nell'immagine, e riguarda un attributo
# del modulo letto a ogni chiamata.
#
# Il valore servito è fissato da
# tests/test_case_manager.py::TestAuthPrimitives::test_served_pbkdf2_cost_is_not_lowered:
# in un interprete pulito (con l'ambiente di questo processo) legge la costante e le
# iterazioni che hash e verifica passano davvero a PBKDF2, quindi questo override non
# può nascondere un calo della costante o delle iterazioni che le due funzioni passano.
#
# `ImportError` si ignora: con `shared` fuori dal percorso di import (un `pytest` senza
# PYTHONPATH) i moduli di test che lo usano falliscono da soli in raccolta, ma i test
# che non lo toccano, come la resa della dashboard, devono restare eseguibili. Questo
# file non deve rompere più di quanto non rompesse prima dell'override. Lo stesso
# `ImportError` può venire da un import interno rotto di `shared/auth.py`: anche lì
# l'errore riemerge nei moduli di test che lo importano, e qui manca solo l'override,
# cioè la suite torna lenta, non meno severa.
try:
    import shared.auth as _auth
except ImportError:
    pass
else:
    _auth.PBKDF2_ITERATIONS = 1000


@pytest.fixture
def sample_dns_result():
    return {
        "domain": "example.com",
        "records": {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 -all"],
        },
        "email_auth": {
            "spf": {"present": True, "records": ["v=spf1 -all"], "policy": "fail"},
            "dmarc": {"present": False, "records": []},
            "dkim": {"selectors_found": [], "selectors_tested": 17, "records": {}},
        }
    }


@pytest.fixture
def sample_http_parking():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 95,
             "hidden_elements": {"risk_indicators": 0, "summary": []}},
        ],
        "overall_status": "active"
    }


@pytest.fixture
def sample_http_real_site():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 45000,
             "hidden_elements": {"risk_indicators": 0, "summary": []}},
        ],
        "overall_status": "active"
    }


@pytest.fixture
def sample_http_suspicious():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 5000,
             "hidden_elements": {
                 "hidden_forms": [{"action": "https://evil.com/steal.php"}],
                 "risk_indicators": 35,
                 "summary": ["1 form nascosti — possibile credential harvesting"]
             }},
        ],
        "overall_status": "active"
    }


# ── Rete WHOIS finta SOTTO il client di python-whois ───────────────────────
#
# Per i test di `services/whois_intel.py` (COL-17): il guasto da riprodurre non sta nel servizio ma
# in ciò che la libreria restituisce quando la connessione al server del registro fallisce, quindi
# il doppio deve stare più in basso possibile. Si sostituisce solo `NICClient.get_socket`: la
# libreria vera sceglie il server, interroga IANA, segue il rinvio al secondo hop, sintetizza il
# testo d'errore e lo passa al parser del TLD. Nessun socket reale viene aperto.

import errno as _errno
import os as _os


class _WhoisFailure:
    """Un guasto della rete: `connect()` o `recv()` sollevano `exc`, la libreria lo trasforma in testo."""

    def __init__(self, name, exc, when):
        self.name, self.exc, self.when = name, exc, when

    @property
    def text(self):
        """Il testo che la libreria incorpora nel proprio messaggio, p.es. `[Errno 111] Connection refused`."""
        return str(self.exc)

    def __repr__(self):
        return f"<{self.name}>"


def _errno_failure(name, number, exc_type, when):
    return _WhoisFailure(name, exc_type(number, _os.strerror(number)), when)


class FakeWhoisNetwork:
    """Server WHOIS finti. Una risposta è il testo servito (anche `""`: il server chiude senza dati)
    oppure uno dei guasti `REFUSED` / `TIMEOUT` / `RESET`. Un host non previsto dal test fa fallire
    il test a fine esecuzione (`unexpected`), anche se la libreria o il servizio ne inghiottono l'errore."""

    REFUSED = _errno_failure("connection-refused", _errno.ECONNREFUSED, ConnectionRefusedError, "connect")
    TIMEOUT = _errno_failure("connection-timed-out", _errno.ETIMEDOUT, TimeoutError, "connect")
    RESET = _errno_failure("connection-reset", _errno.ECONNRESET, ConnectionResetError, "recv")

    REGISTRY = "whois.registry.example"      # il registro dei TLD che passano da IANA
    REGISTRAR = "whois.registrar.example"    # il secondo hop (com/net): va nominato dal testo del registro

    def __init__(self, nic):
        self.nic = nic
        # I TLD con server statico non passano da IANA: la libreria li conosce da sé.
        self._static = {"de": nic.NICClient.DE_HOST, "nl": nic.NICClient.NL_HOST}
        self.answers = {}
        self.contacted, self.unexpected = [], []
        self.iana()

    def iana(self, answer=None):
        """`None`: IANA indirizza al registro, il comportamento normale."""
        if answer is None:
            answer = f"refer: x\n\nwhois:        {self.REGISTRY}\n"
        self.answers[self.nic.NICClient.IANAHOST] = answer

    def registry(self, tld, answer):
        self.answers[self._static.get(tld, self.REGISTRY)] = answer

    def registrar(self, answer):
        self.answers[self.REGISTRAR] = answer

    def socket(self):
        return _FakeWhoisSocket(self)


class _FakeWhoisSocket:
    def __init__(self, network):
        self.network, self.payload, self.failure = network, b"", None

    def settimeout(self, seconds):
        pass

    def connect(self, address):
        host = address[0]
        self.network.contacted.append(host)
        if host not in self.network.answers:
            self.network.unexpected.append(host)
            raise AssertionError(f"il test non prevede il server WHOIS {host}")
        answer = self.network.answers[host]
        if isinstance(answer, _WhoisFailure):
            if answer.when == "connect":
                raise answer.exc
            self.failure = answer
        else:
            self.payload = answer.encode()

    def send(self, data):
        pass

    def recv(self, size):
        if self.failure is not None:
            raise self.failure.exc
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk

    def close(self):
        pass


@pytest.fixture
def whois_network(monkeypatch):
    import importlib
    nic = importlib.import_module("whois.whois")    # il modulo del client; `whois.whois` del package è la funzione
    network = FakeWhoisNetwork(nic)
    monkeypatch.setattr(nic.NICClient, "get_socket", staticmethod(network.socket))
    yield network
    assert not network.unexpected, f"server WHOIS non previsti: {network.unexpected}"


# ── BUILD-09: la suite divisa fra più processi (tests/run_parallel.py) ─────
#
# Con DS_TEST_SHARD="k/n" il processo raccoglie l'intera suite ma esegue solo la parte k di n
# (numerate da 1): N processi insieme fanno la suite in una frazione del tempo con la sola
# libreria standard. Assente o vuota: nessun effetto. Presente ma malformata ferma la sessione:
# ignorarla ripeterebbe la suite intera in ogni processo senza dirlo.
#
# Si divide per gruppi, non per test: una classe, perché i suoi test condividono stato; il
# modulo intero se ha setup/teardown di modulo, che preparano o ripristinano stato fuori dal
# modulo (ambiente, moduli ricaricati, percorsi fissi in /tmp) e devono girare una volta sola.
# La parte di un gruppo è crc32 del suo nodeid modulo n: uguale in ogni processo, mentre il
# seme di `hash()` cambia da un interprete all'altro.
#
# Con DS_TEST_SHARD_REPORT il processo scrive lì i test raccolti (prima della scelta) e quelli
# eseguiti con l'esito: il driver verifica che l'unione delle parti sia esattamente la suite,
# perché un test che nessuna parte esegue lascia ogni processo a exit 0.
import json as _json
import re as _re
import signal as _signal
import zlib as _zlib

_DS_PARTE = pytest.StashKey()
_DS_MODULO_INTERO = ("setup_module", "setUpModule", "teardown_module", "tearDownModule")
_ds_rapporto = {"raccolti": [], "eseguiti": []}


def pytest_configure(config):
    valore = _os.environ.get("DS_TEST_SHARD", "")
    if not valore:
        return
    trovato = _re.fullmatch(r"([0-9]+)/([0-9]+)", valore)
    if not trovato or not 1 <= int(trovato[1]) <= int(trovato[2]):
        raise pytest.UsageError(f"DS_TEST_SHARD={valore!r} non valida: atteso k/n con 1 <= k <= n")
    config.stash[_DS_PARTE] = (int(trovato[1]), int(trovato[2]))
    # Il driver ferma una parte con SIGTERM (SIGHUP se si chiude il terminale). Come KeyboardInterrupt pytest esegue
    # i teardown, e le fixture fermano anche ciò che hanno avviato fuori dal gruppo della parte. Solo in una parte, e
    # solo con la disposizione di default: un segnale ricevuto già ignorato resta ignorato.
    for numero in (_signal.SIGTERM, _signal.SIGHUP):
        if _signal.getsignal(numero) == _signal.SIG_DFL:
            _signal.signal(numero, _ds_interrompi)


def _ds_interrompi(_numero, _frame):
    raise KeyboardInterrupt


def _ds_gruppo(item):
    modulo = item.getparent(pytest.Module)
    if modulo is None:
        return item.nodeid
    if any(hasattr(modulo.obj, nome) for nome in _DS_MODULO_INTERO):
        return modulo.nodeid
    return next((nodo for nodo in item.listchain() if isinstance(nodo, pytest.Class)), modulo).nodeid


@pytest.hookimpl(trylast=True)    # dopo -k, -m e --deselect: la suite è ciò che pytest eseguirebbe
def pytest_collection_modifyitems(config, items):
    _ds_rapporto["raccolti"] = [item.nodeid for item in items]
    if _DS_PARTE not in config.stash:
        return
    k, n = config.stash[_DS_PARTE]
    tenuti, tolti = [], []
    for item in items:
        (tenuti if _zlib.crc32(_ds_gruppo(item).encode()) % n == k - 1 else tolti).append(item)
    items[:] = tenuti
    if tolti:
        config.hook.pytest_deselected(items=tolti)


def pytest_runtest_logreport(report):
    # Setup, call e teardown arrivano in fila per ogni test: il setup apre la voce, poi vale il
    # primo esito diverso da "passed" (setup o teardown falliti: "error"), altrimenti la call.
    if report.when == "setup":
        _ds_rapporto["eseguiti"].append([report.nodeid, "passed"])
    voce = _ds_rapporto["eseguiti"][-1]
    if voce[1] == "passed" and (report.when == "call" or not report.passed):
        voce[1] = report.outcome if report.when == "call" or report.skipped else "error"


def pytest_sessionfinish(session):
    percorso = _os.environ.get("DS_TEST_SHARD_REPORT")
    if percorso:
        with open(percorso, "w") as f:
            _json.dump(_ds_rapporto, f)
