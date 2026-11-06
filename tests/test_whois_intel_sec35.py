"""Tests for services/whois_intel.py — una risposta WHOIS ostile non deve bloccare il processo (SEC-35).

Il servizio gira nello stesso processo degli altri router (`unified`) e legge ciò che i server WHOIS
rispondono: il server radice, il registro, il server del registrar nominato dal registro. Una risposta lunga o
costruita ad arte può costare CPU con il GIL tenuto (le regex di `python-whois` sono super-lineari: una riga
lunga senza `@`, spazi dopo «Technical: Name:» per `.eu`, spazi dopo «Domain Name: <dominio>» o «whois:»)
oppure memoria e tempo di rete (nessun tetto ai byte, nessuna scadenza totale, un rinvio `=xxx` ripetuto
senza fine). Finché dura, dashboard, sonde di salute e login dello stesso processo non rispondono.

Comportamento richiesto:

- La rete ha un budget: una scadenza TOTALE del lookup (`WHOIS_LOOKUP_DEADLINE_S`, 15 s, compresi server
  radice, registro, registrar e rinvii), un tetto di byte per connessione (server radice
  `WHOIS_IANA_MAX_BYTES` 8 KB, primo hop `WHOIS_FIRST_HOP_MAX_BYTES` 8 KB) e uno totale
  (`WHOIS_TOTAL_MAX_BYTES`, 64 KB), un numero massimo di connessioni (`WHOIS_MAX_CONNECTIONS`, 5, server
  radice compreso). Al superamento dei byte si smette di leggere e si tiene il testo letto: è un
  troncamento, non un errore, quindi i campi che stanno nei primi KB restano un'osservazione.
- Il parsing avviene in un processo figlio con limite di CPU (`WHOIS_PARSE_CPU_S`, 4 s) e di parete
  (`WHOIS_PARSE_TIMEOUT_S`, 8 s). Se il figlio muore, scade o fallisce, l'esito è un errore di raccolta con
  un testo fisso del servizio (mai il testo della risposta, di un errno, di un host o l'output del figlio),
  con la forma di un lookup fallito. Un'eccezione del parser con un testo proprio (es. «No match for…») resta
  un errore con quel testo, che il figlio tronca a 1024 caratteri: `sanitize_error` riceve abbastanza testo
  per redigere e per troncare a 200 caratteri più «...», e non lavora sul testo intero.
- Il figlio interpreta testo di terzi, quindi: dall'ambiente riceve solo una lista bianca (`PATH`, `LANG`,
  `LC_ALL`, `LC_CTYPE`, `TZ`, `LD_LIBRARY_PATH`, se presenti), non scrive core dump e abbassa la propria
  priorità (`os.nice(10)`), tutto prima di leggere l'input. Al più `WHOIS_PARSE_MAX_CHILDREN` (4) figli vivi
  insieme: chi non ottiene un posto entro `WHOIS_PARSE_TIMEOUT_S` ha un errore di raccolta con testo fisso
  (`WHOIS_PARSE_BUSY_ERROR`), e il posto si libera a ogni esito (riuscita, errore del parser, avvio fallito,
  scadenza, eccezione qualunque).
- La causa di un guasto di rete resta nel log: la scrive la libreria nel suo logger (`whois.whois`), che il
  servizio non mette a tacere.
- Le risposte leggibili producono i campi attesi, campo per campo (date comprese, con o senza fuso).

I limiti sono costanti di modulo lette al momento del lookup: i test le abbassano con `monkeypatch`
(`raising=False`, così un servizio che non le conosce fallisce per il suo comportamento e non per un
`AttributeError`) per tenere brevi le attese reali (scadenza totale, limite di CPU e di parete del figlio,
posti per i figli). Un test fissa i valori di default.

Come si misura. Il servizio vero (GET /whois via TestClient) gira in un thread, con un secondo thread di
battito nello stesso processo: il massimo intervallo fra due suoi risvegli è per quanto il GIL è
rimasto occupato. Le dimensioni delle risposte ostili sono scelte perché il costo sia netto ma limitato.
I tempi sono interi della richiesta, rete finta inclusa.

Isolamento di rete: **nessuna connessione reale**. I server sono finti sotto il `NICClient` vero di
`python-whois` (si sostituisce solo `NICClient.get_socket`): la libreria sceglie il server, interroga il
server radice, segue il rinvio al secondo hop e legge con il proprio ciclo `recv`, come in produzione. Le
risposte di dimensione normale usano la fixture `whois_network` (tests/conftest.py); quelle a flusso (gocciolamento,
risposte enormi, rinvii senza fine) usano un doppio con lo stesso contratto del socket, che sa fermarsi
e rispettare `settimeout`. Per i rami del figlio che fallisce, un test sostituisce `subprocess.Popen` con un
doppio; per ciò che si vede solo da fuori (ambiente, priorità, limiti, quanti figli vivono insieme) un
sottotipo di `Popen` lancia il figlio vero e lo osserva da `/proc` prima che legga l'input. I nomi di dominio e
di server sono finti (`.example`), tranne dove il parser di un TLD o la libreria li richiede per riconoscere
il formato.

Il caso del registro che non risponde e dei campi assenti è in `tests/test_whois_intel.py`.
"""
import contextlib
import functools
import importlib
import logging
import os
import re
import resource
import socket
import subprocess
import sys
import threading
import time
import tracemalloc
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import services.whois_intel as whois_service
from shared.security import sanitize_error

# `whois.whois` del package è la funzione `whois`: il modulo del client si prende da importlib.
NICClient = importlib.import_module("whois.whois").NICClient

COM = "acme-typo.com"
DE = "acme-typo.de"
IT = "acme-typo.it"
EU = "acme-typo.eu"
HK = "acme-typo.hk"
ORG = "acme-typo.org"

# Gli host che la libreria conosce da sé sono le sue costanti, mai letterali. «IANA» è il nome che la libreria
# (`findwhois_iana`) e le costanti del servizio (`WHOIS_IANA_MAX_BYTES`) danno al server radice, non un
# riferimento a un'organizzazione.
IANA = NICClient.IANAHOST
HK_REGISTRY = NICClient.HK_HOST          # il registro di .hk: la libreria lo conosce da sé, senza server radice
REGISTRY = "whois.registry.example"      # il registro dei TLD che passano dal server radice (come in conftest)
REGISTRAR = "whois.registrar.example"    # il secondo hop (com/net/org): lo nomina il testo del registro

# Il testo fisso che il servizio dà a un lookup senza posto per il figlio: vive sia nel servizio sia qui, così
# un test sul comportamento non dipende da una costante che il servizio potrebbe non avere.
_BUSY_ERROR = "WHOIS lookup failed: too many responses are being parsed"
_FAILED_ERROR = "WHOIS lookup failed: the response could not be parsed"

# Stato EPP seguito da un URL: la forma che i registri danno al campo `Status`, e che il parser conserva intera.
_COM_STATUS = "clientTransferProhibited https://registry.example/epp#clientTransferProhibited"


# ── Risposte dei server ────────────────────────────────────────────────────

def _com_registry(registrar_server):
    """Record sottile del registro .com con il testo legale in coda. Se `registrar_server` è un host,
    il record lo nomina (la libreria lo cerca dopo «Whois Server:») e interroga anche quello."""
    referral = f"   Registrar WHOIS Server: {registrar_server}\r\n" if registrar_server else ""
    return ("   Domain Name: ACME-TYPO.COM\r\n"
            "   Registry Domain ID: 1_DOMAIN_COM-EX\r\n"
            + referral +
            "   Registrar URL: http://www.registrar.example\r\n"
            "   Updated Date: 2026-05-01T10:00:00Z\r\n"
            "   Creation Date: 2020-01-01T00:00:00Z\r\n"
            "   Registry Expiry Date: 2027-01-01T00:00:00Z\r\n"
            "   Registrar: Registrar Example Inc.\r\n"
            "   Registrar ID: 9999\r\n"
            "   Registrar Abuse Contact Email: abuse@registrar.example\r\n"
            "   Registrar Abuse Contact Phone: +1.5555550100\r\n"
            f"   Domain Status: {_COM_STATUS}\r\n"
            "   Name Server: NS1.ACME-TYPO.COM\r\n"
            "   Name Server: NS2.ACME-TYPO.COM\r\n"
            "   DNSSEC: unsigned\r\n"
            "   URL of the Whois Inaccuracy Complaint Form: https://registry.example/wicf/\r\n"
            ">>> Last update of whois database: 2026-10-31T00:00:00Z <<<\r\n\r\n"
            "TERMS OF USE: You are not authorized to access or query our Whois database through the use of\r\n"
            "electronic processes that are high-volume and automated except as reasonably necessary to\r\n"
            "register domain names or modify existing registrations; the Data in the registry Whois database\r\n"
            "is provided for information purposes only, and to assist persons in obtaining information about\r\n"
            "or related to a domain name registration record. By submitting a Whois query, you agree to abide\r\n"
            "by these terms of use. The Registry database contains ONLY .COM, .NET, .EDU domains and\r\n"
            "Registrars.\r\n")


# Il testo legale dei registrar è spesso una riga unica di ~1,7 KB con spazi.
_LEGAL_LINE = ("The data in this whois database is provided to you for information purposes only, that is, to "
               "assist you in obtaining information about or related to a domain name registration record. "
               "We make this information available \"as is,\" and do not guarantee its accuracy. By "
               "submitting a whois query, you agree that you will use this data only for lawful purposes and "
               "that, under no circumstances will you use this data to: (1) enable high volume, automated, "
               "electronic processes that stress or load this whois database system providing you this "
               "information; or (2) allow, enable, or otherwise support the transmission of mass unsolicited, "
               "commercial advertising or solicitations via direct mail, electronic mail, or by telephone. "
               "The compilation, repackaging, dissemination or other use of this data is expressly prohibited "
               "without prior written consent from us. ") * 2


def _contact_block(role):
    fields = (("Name", "Reg Name"), ("Organization", "Reg Name Srl"), ("Street", "Via Esempio 1"),
              ("City", "Milano"), ("State/Province", "MI"), ("Postal Code", "20100"), ("Country", "IT"),
              ("Phone", "+39.0200000000"), ("Email", "reg@acme-typo.example"))
    return "".join(f"{role} {key}: {value}\r\n" for key, value in fields)


def _thick_registrar():
    """Record del secondo hop (server del registrar) con registrante, admin, tech e testo legale."""
    return ("Domain Name: acme-typo.com\r\n"
            "Registry Domain ID: 1_DOMAIN_COM-EX\r\n"
            "Registrar WHOIS Server: whois.registrar.example\r\n"
            "Registrar URL: http://www.registrar.example\r\n"
            "Updated Date: 2026-05-01T10:00:00Z\r\n"
            "Creation Date: 2020-01-01T00:00:00Z\r\n"
            "Registrar Registration Expiration Date: 2027-01-01T00:00:00Z\r\n"
            "Registrar: Registrar Example Inc.\r\n"
            "Domain Status: clientTransferProhibited\r\n"
            + _contact_block("Registrant") + _contact_block("Admin") + _contact_block("Tech") +
            "Name Server: NS1.ACME-TYPO.COM\r\n"
            "Name Server: NS2.ACME-TYPO.COM\r\n"
            "DNSSEC: unsigned\r\n"
            "Registrar Abuse Contact Email: abuse@registrar.example\r\n\r\n"
            + _LEGAL_LINE + "\r\n")


_REGISTRANT_VISIBLE = ("Registrant Name: Reg Name\r\n"
                       "Registrant Organization: Reg Name Srl\r\n"
                       "Registrant Country: ZZ\r\n")

_DE_RECORD = ("Domain: acme-typo.de\n"
              "Nserver: ns1.acme-typo.de\n"
              "Nserver: ns2.acme-typo.de\n"
              "Status: connect\n"
              "Changed: 2026-05-01T10:00:00+02:00\n")

_IT_RECORD = ("*********************************************************************\n"
              "* Please note that the following result could be a subgroup of the data *\n"
              "* contained in the database.                                        *\n"
              "*********************************************************************\n\n"
              "Domain:             acme-typo.it\n"
              "Status:             ok\n"
              "Signed:             no\n"
              "Created:            2020-01-01 00:00:00\n"
              "Last Update:        2026-05-01 10:00:00\n"
              "Expire Date:        2027-01-01\n\n"
              "Registrant\n"
              "  Organization:     Reg Name Srl\n"
              "  Address:          Via Esempio 1\n"
              "                    Milano\n"
              "                    20100\n"
              "                    MI\n"
              "                    IT\n"
              "  Created:          2020-01-01 00:00:00\n"
              "  Last Update:      2026-05-01 10:00:00\n\n"
              "Admin Contact\n"
              "  Name:             Reg Name\n"
              "  Organization:     Reg Name Srl\n\n"
              "Registrar\n"
              "  Organization:     Registrar Example\n"
              "  Name:             REG-EXAMPLE\n"
              "  Web:              https://registrar.example\n\n"
              "Nameservers\n"
              "  ns1.acme-typo.it\n"
              "  ns2.acme-typo.it\n")

_EU_HEADER = ("% The WHOIS service offered by the registry and the access to the records\n"
              "% in the registry WHOIS database are provided for information purposes\n"
              "% only. It allows persons to check whether a specific domain name\n"
              "% is still available or not and to obtain information related to\n"
              "% the registration records of existing domain names.\n%\n"
              "% Please visit https://registry.example for more info.\n\n")
_EU_BODY = ("Domain: acme-typo.eu\n"
            "Script: LATIN\n\n"
            "Registrant:\n"
            "        NOT DISCLOSED!\n"
            "        Visit www.registry.example for the web-based WHOIS.\n\n"
            "Registrar:\n"
            "        Name: Registrar Example\n"
            "        Website: https://registrar.example\n\n"
            "Name servers:\n"
            "        ns1.acme-typo.eu\n"
            "        ns2.acme-typo.eu\n\n")
_EU_RECORD = (_EU_HEADER
              + "Domain: acme-typo.eu\n"
                "Script: LATIN\n\n"
                "Registrant:\n"
                "        NOT DISCLOSED!\n"
                "        Visit www.registry.example for the web-based WHOIS.\n\n"
                "Technical:\n"
                "        Organisation: Registrar Example\n"
                "        Language: en\n"
                "        Email: tech@registrar.example\n\n"
                "Registrar:\n"
                "        Name: Registrar Example\n"
                "        Website: https://registrar.example\n\n"
                "Name servers:\n"
                "        ns1.acme-typo.eu\n"
                "        ns2.acme-typo.eu\n\n"
                "Keys:\n"
                "        flags:KSK protocol:3 algorithm:ECDSAP256SHA256 pubKey:" + "A" * 88 + "\n\n"
                "Please visit www.registry.example for more info.\n")

_ORG_RECORD = ("Domain Name: ACME-TYPO.ORG\r\n"
               "Registry Domain ID: D1-EX\r\n"
               "Registrar WHOIS Server: whois.registrar.example\r\n"
               "Registrar URL: http://www.registrar.example\r\n"
               "Updated Date: 2026-05-01T10:00:00Z\r\n"
               "Creation Date: 2020-01-01T00:00:00Z\r\n"
               "Registry Expiry Date: 2027-01-01T00:00:00Z\r\n"
               "Registrar: Registrar Example Inc.\r\n"
               "Registrar ID: 9999\r\n"
               "Domain Status: clientTransferProhibited\r\n"
               "Registrant Organization: Reg Name Srl\r\n"
               "Registrant State/Province: MI\r\n"
               "Registrant Country: IT\r\n"
               "Name Server: NS1.ACME-TYPO.ORG\r\n"
               "Name Server: NS2.ACME-TYPO.ORG\r\n"
               "DNSSEC: unsigned\r\n"
               "URL of the Whois Inaccuracy Complaint Form: https://registry.example/wicf/\r\n"
               ">>> Last update of WHOIS database: 2026-10-31T00:00:00Z <<<\r\n\r\n"
               + ("Access to the registry WHOIS information is provided to assist persons in "
                  "determining the contents of a domain name registration record in the registry "
                  "database. ") * 3 + "\r\n")

_NOT_REGISTERED_COM = ('No match for "ACME-TYPO.COM".\r\n'
                       ">>> Last update of whois database: 2026-10-31T00:00:00Z <<<\r\n")

# Righe di riempimento: lunghe come quelle dei record veri, senza campi e senza `@`.
_PADDING_LINE = "x" * 79 + "\n"

# Quanto manda un server che inonda il client: oltre 10 volte il tetto totale di lettura (un client senza
# tetto lo legge tutto).
_FLOOD = 700_000


# ── Rete finta a flusso ────────────────────────────────────────────────────

class _Net:
    """Server WHOIS finti a flusso, sotto il `NICClient` vero. La risposta di un server è un testo, dei
    byte oppure una funzione che ritorna un iteratore di pezzi: `bytes` (disponibili subito) e `float`
    (il server tace per quei secondi). Registra le connessioni e i byte consegnati al client, e un host
    non previsto dal test fa fallire il test. `abort` ferma ogni server (la lettura vede la fine del
    flusso): serve a non lasciare thread in attesa."""

    def __init__(self):
        self.scripts = {}
        self.contacted = []
        self.delivered = {}
        self.unexpected = []
        self.abort = threading.Event()
        self.serve(IANA, f"refer: x\n\nwhois:        {REGISTRY}\n")

    def serve(self, host, answer):
        if callable(answer):
            self.scripts[host] = answer
        else:
            data = answer.encode() if isinstance(answer, str) else answer
            self.scripts[host] = lambda: iter([data])

    def socket(self):
        return _StreamSocket(self)

    def connections_to(self, host):
        return self.contacted.count(host)

    @property
    def delivered_total(self):
        return sum(self.delivered.values())


class _StreamSocket:
    def __init__(self, net):
        self.net, self.timeout, self.host = net, None, None
        self.chunks, self.pending = iter(()), b""

    def settimeout(self, seconds):
        self.timeout = seconds

    def connect(self, address):
        self.host = address[0]
        self.net.contacted.append(self.host)
        script = self.net.scripts.get(self.host)
        if script is None:
            self.net.unexpected.append(self.host)
            raise AssertionError(f"il test non prevede il server WHOIS {self.host}")
        self.chunks = iter(script())

    def send(self, data):
        return len(data)

    def recv(self, size):
        while not self.pending:
            if self.net.abort.is_set():
                return b""
            item = next(self.chunks, None)
            if item is None:
                return b""
            if isinstance(item, float):
                self._wait(item)
            else:
                self.pending = item
        data, self.pending = self.pending[:size], self.pending[size:]
        self.net.delivered[self.host] = self.net.delivered.get(self.host, 0) + len(data)
        return data

    def _wait(self, pause):
        """Come un socket vero: se il dato arriva dopo la scadenza dell'operazione, `recv` scade."""
        if self.timeout is not None and pause > self.timeout:
            self.net.abort.wait(self.timeout)
            raise socket.timeout("timed out")
        self.net.abort.wait(pause)

    def close(self):
        pass


class _TimeoutAtConnectSocket(_StreamSocket):
    """Come `_StreamSocket`, e registra il timeout in vigore sul socket vero nel momento in cui si collega: un
    `connect` senza timeout (o con quello della libreria, 10 s) resterebbe bloccato quanto il sistema operativo
    vuole, oltre la scadenza del lookup."""

    def connect(self, address):
        self.net.timeouts_at_connect.append((address[0], self.timeout))
        super().connect(address)


class _RecordingNet(_Net):
    def __init__(self):
        super().__init__()
        self.timeouts_at_connect = []

    def socket(self):
        return _TimeoutAtConnectSocket(self)


def _flood(head, total):
    """Un server che manda `head` e poi righe di riempimento fino a `total` byte: il flusso è finito, ma
    un client senza tetto lo legge tutto."""
    def script():
        yield head.encode() if isinstance(head, str) else head
        block = (_PADDING_LINE * 1000).encode()
        for _ in range(total // len(block)):
            yield block
    return script


def _silent_then(pause, data):
    """Un server che tace `pause` secondi (un `float`: così lo legge `_StreamSocket`) e poi manda `data`."""
    def script():
        yield pause
        yield data.encode() if isinstance(data, str) else data
    return script


def _drip():
    """Un server che manda un byte ogni mezzo secondo, senza fine e senza mai un campo."""
    yield b"\n"
    while True:
        yield 0.5
        yield b" "


def _nic():
    return importlib.import_module("whois.whois")    # il modulo del client; `whois.whois` del package è la funzione


@contextlib.contextmanager
def _service_over(net, limits=None, popen=None):
    """Il servizio con cache vuota, senza attesa fra le richieste e con la rete finta sotto la libreria.
    `limits` abbassa costanti di modulo (`raising=False`: un servizio che non le ha le ignora); `popen`
    sostituisce `subprocess.Popen` (un sottotipo che lancia comunque il figlio vero)."""
    with pytest.MonkeyPatch.context() as patch:
        for name, value in (limits or {}).items():
            patch.setattr(whois_service, name, value, raising=False)
        if popen is not None:
            patch.setattr(whois_service.subprocess, "Popen", popen)
        patch.setattr(whois_service, "WHOIS_DELAY", 0.0)
        patch.setattr(whois_service, "HAS_WHOIS_LIB", True)
        patch.setattr(whois_service, "_cache", {})
        patch.setattr(whois_service, "_cache_order", [])
        patch.setattr(_nic().NICClient, "get_socket", staticmethod(net.socket))
        yield


class _Heartbeat:
    """Un thread che dorme 5 ms in ciclo: l'intervallo massimo fra due risvegli dice per quanto un
    altro thread del processo è rimasto fermo, cioè per quanto il GIL è stato tenuto da qualcun altro."""

    def __init__(self):
        self.gaps, self.stopped = [], False

    def __enter__(self):
        def beat():
            last = time.perf_counter()
            while not self.stopped:
                time.sleep(0.005)
                now = time.perf_counter()
                self.gaps.append(now - last)
                last = now
        self.thread = threading.Thread(target=beat, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.gaps.clear()
        return self

    def __exit__(self, *exc):
        self.stopped = True
        self.thread.join()

    @property
    def longest_stall(self):
        return max(self.gaps) if self.gaps else 0.0


def _cpu_spent():
    """CPU consumata dal processo di test (tutti i suoi thread) e dai figli attesi, da quando il processo è nato:
    se ne prendono differenze. È ciò che una risposta ostile costa davvero: il tempo di parete dipende anche da
    quanta CPU lasciano gli altri processi."""
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time(), children.ru_utime + children.ru_stime


class _Run:
    """Una richiesta GET /whois fatta in un thread: durata, corpo, di quanto un thread di battito è rimasto
    fermo mentre durava e quanta CPU ha consumato (processo e figli)."""

    def __init__(self, net):
        self.net = net
        self.cpu_self = self.cpu_children = None
        self.done = False
        self.crash = None
        self.status = self.body = None
        self.elapsed = None
        self.stall = None
        self.peak_memory = None
        self.thread = None

    def start(self, domain):
        api = TestClient(whois_service.app)

        def call():
            started = time.perf_counter()
            try:
                response = api.get("/whois", params={"domain": domain})
                self.status, self.body = response.status_code, response.json()
            except Exception as exc:    # un thread che muore in silenzio lascerebbe il test senza spiegazione
                self.crash = exc
            self.elapsed = time.perf_counter() - started
            self.done = True

        self.started = time.perf_counter()
        self.thread = threading.Thread(target=call, daemon=True)
        self.thread.start()

    def wait(self, seconds):
        self.thread.join(max(0.0, seconds))
        return self.done

    def describe(self):
        """Una riga per i messaggi di errore."""
        if self.crash is not None:
            return f"la richiesta è fallita con {self.crash!r}"
        if not self.done:
            return f"la richiesta non è finita in {time.perf_counter() - self.started:.1f} s"
        return f"HTTP {self.status} in {self.elapsed:.2f} s, errore {self.body.get('error')!r}"


def _perform(net, domain, wait, trace_memory=False, limits=None):
    """Esegue la richiesta con un thread di battito a fianco. Se non finisce entro `wait` secondi ferma i
    server finti, così il thread del servizio non resta appeso."""
    run = _Run(net)
    with _service_over(net, limits), _Heartbeat() as beat:
        if trace_memory:
            tracemalloc.start()
        spent_before = _cpu_spent()
        try:
            run.start(domain)
            if not run.wait(wait):
                net.abort.set()
                run.wait(10)
        finally:
            if trace_memory:
                run.peak_memory = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
        spent_after = _cpu_spent()
    run.cpu_self = spent_after[0] - spent_before[0]
    run.cpu_children = spent_after[1] - spent_before[1]
    run.stall = beat.longest_stall
    assert not net.unexpected, f"server WHOIS non previsti: {net.unexpected}"
    assert run.crash is None, run.describe()
    return run


# ── Scenari ostili (ognuno gira una volta sola per modulo) ─────────────────
#
# Una richiesta ostile su un servizio senza difese costa secondi di CPU: due test che leggono lo stesso
# scenario (durata, blocco degli altri thread, esito) ne condividono l'esecuzione.

_SCENARIOS = {}

# Limiti abbassati per le attese reali: il figlio che fa il parsing viene fermato a 1 s di CPU (default 4 s)
# e la scadenza totale di un server che goccia è di 0,6 s (default 15 s). Un servizio che li ignora resta
# entro i limiti di durata dei test, ma con le attese di default; il test sui default li fissa.
_CPU_LIMIT = {"WHOIS_PARSE_CPU_S": 1}
# Dove si misura che il figlio è fermato dal limite di CPU, la parete è larga: se bastasse la parete (8 s di
# default) a fermarlo, un figlio senza limite di CPU passerebbe il test pur consumando fino alla parete.
_CPU_LIMIT_ONLY = {"WHOIS_PARSE_CPU_S": 1, "WHOIS_PARSE_TIMEOUT_S": 60}
_DRIP_DEADLINE = 0.6


def _scenario(function):
    _SCENARIOS[function.__name__] = function
    return function


def _warm_up():
    """Una richiesta qualunque prima di misurare la memoria: le importazioni pigre della prima richiesta del
    processo non sono costo del lookup."""
    net = _Net()
    net.serve(REGISTRY, _com_registry(None))
    _perform(net, COM, wait=40)


@functools.cache
def _run(name):
    net = _Net()
    domain, options = _SCENARIOS[name](net)
    if options.get("trace_memory"):
        _warm_up()
    return _perform(net, domain, wait=options.get("wait", 40), trace_memory=options.get("trace_memory", False),
                    limits=options.get("limits"))


@_scenario
def long_line_in_the_second_hop(net):
    # Una riga senza `@` nel record del registrar: la regex degli indirizzi è quadratica.
    net.serve(REGISTRY, _com_registry(REGISTRAR))
    net.serve(REGISTRAR, _REGISTRANT_VISIBLE + "z" * 13_000)
    return COM, {"limits": _CPU_LIMIT}


_RAW_MARKER = "raw-registry-text-marker-5d1f"


@_scenario
def eu_technical_name_followed_by_spaces(net):
    # Il parser di .eu ha una regex cubica sugli spazi dopo «Technical: Name:». Il record ha i campi
    # in testa: un parser che non finisce non deve lasciare un'osservazione parziale.
    net.serve(REGISTRY, _EU_HEADER + f"Remarks: {_RAW_MARKER}\n" + _EU_BODY + "Technical: Name:" + " " * 1_000)
    return EU, {"limits": _CPU_LIMIT_ONLY}


@_scenario
def hk_record_without_the_expected_field(net):
    # Il parser di .hk è quadratico nella dimensione del testo quando il campo atteso manca.
    net.serve(HK_REGISTRY, "Domain Name: ACME-TYPO.HK\n" * (4_500 // 26))
    return HK, {"limits": _CPU_LIMIT_ONLY}


@_scenario
def spaces_after_domain_name_in_the_first_hop(net):
    # `findwhois_server` cerca «Domain Name: <dominio>\s*.*?Whois Server:» sul primo hop: quadratica.
    net.serve(REGISTRY, "Domain Name: acme-typo.com" + " " * 26_000)
    return COM, {}


@_scenario
def spaces_after_whois_in_the_iana_answer(net):
    # La riga «whois:» del server radice si cerca con `whois:\s+(.*?)\n`; senza il fine riga è quadratica.
    net.serve(IANA, "whois:" + " " * 24_000)
    return COM, {}


@_scenario
def repeated_domain_name_lines(net):
    # Ogni «Domain Name: <dominio>» riparte da capo la ricerca del server del registrar.
    net.serve(REGISTRY, "Domain Name: acme-typo.com\n" * (90_000 // 27))
    return COM, {}


@_scenario
def parser_exception_with_a_long_text(net):
    # Il parser solleva con l'intero testo della risposta («No match for»), che il servizio sanifica e taglia
    # a 200 caratteri.
    net.serve(REGISTRY, _com_registry(REGISTRAR))
    net.serve(REGISTRAR, _NOT_REGISTERED_COM + "/" * 48_000)
    return COM, {}


@_scenario
def first_hop_flood(net):
    # Un registro che manda megabyte. Si traccia la memoria: la risposta intera in RAM sarebbe vistosa.
    net.serve(REGISTRY, _flood(_com_registry(None), _FLOOD))
    return COM, {"trace_memory": True}


@_scenario
def second_hop_flood(net):
    net.serve(REGISTRY, _com_registry(REGISTRAR))
    net.serve(REGISTRAR, _flood(_REGISTRANT_VISIBLE, _FLOOD // 2))
    return COM, {}


@_scenario
def iana_flood(net):
    # La riga «whois:» sta in testa; segue una risposta enorme.
    net.serve(IANA, _flood(f"refer: x\n\nwhois:        {REGISTRY}\n", _FLOOD // 2))
    net.serve(REGISTRY, _com_registry(None))
    return COM, {}


_EQUALS_XXX = 'look it up with "=xxx" for full display.\r\n'


@_scenario
def equals_xxx_referral_loop_short_replies(net):
    # Ogni risposta del registro chiede di ripetere la richiesta con «=xxx», senza fine: ~45 byte per risposta,
    # quindi il tetto di byte da solo non ferma il rinvio prima del limite di ricorsione dell'interprete.
    net.serve(REGISTRY, _EQUALS_XXX)
    return COM, {}


@_scenario
def equals_xxx_referral_loop_long_replies(net):
    net.serve(REGISTRY, _EQUALS_XXX + "y" * 20_000)
    return COM, {}


@_scenario
def dripping_server(net):
    # Un byte ogni mezzo secondo non fa mai scadere il timeout della singola operazione (10 s): la richiesta
    # finisce solo se il lookup, nel suo insieme, ha una scadenza. Su un servizio senza scadenza non finisce:
    # si ferma il server dopo `wait`.
    net.serve(REGISTRY, _drip)
    return COM, {"limits": {"WHOIS_LOOKUP_DEADLINE_S": _DRIP_DEADLINE}, "wait": _DRIP_DEADLINE + 2.3}


# Tetti di byte diversi per il server radice e per il registro (di default sono uguali, e un tetto scambiato o
# applicato alla connessione sbagliata non si vedrebbe). Il secondo hop non ha un tetto proprio: vale il totale.
_IANA_CAP, _FIRST_HOP_CAP = 2048, 12288


@_scenario
def different_byte_caps_per_connection(net):
    # Ogni server manda molto più del proprio tetto. Il registro nomina il registrar nella prima riga utile.
    net.serve(IANA, _flood(f"refer: x\n\nwhois:        {REGISTRY}\n", 80_000))
    net.serve(REGISTRY, _flood(_com_registry(REGISTRAR), 80_000))
    net.serve(REGISTRAR, _flood(_REGISTRANT_VISIBLE, 80_000))
    return COM, {"limits": {"WHOIS_IANA_MAX_BYTES": _IANA_CAP, "WHOIS_FIRST_HOP_MAX_BYTES": _FIRST_HOP_CAP}}


# ── Fixture ────────────────────────────────────────────────────────────────

# I modi in cui un processo può abbassare la propria priorità: un figlio che lo fa in uno qualunque ha lo stesso
# effetto, e le iniezioni qui sotto li trattano tutti, così una riscrittura del figlio non rompe i test.
_PRIORITY_CALLS = ("nice", "setpriority", "sched_setscheduler")

# Il figlio abbassa la priorità (nice 10): con altri processi che si contendono i core riceve una frazione della CPU
# e la sua durata di parete non misura più nulla (con 8 processi su 4 core 1 s di CPU del parser ne vale 8). La
# priorità ha i suoi test, che girano sul figlio vero; gli altri la lasciano com'è nel processo di test.
_KEEP_PRIORITY = (
    "import os\n"
    "def _keep(*_, **__):\n"
    "    return 0\n"
    f"for _name in {_PRIORITY_CALLS!r}:\n"
    "    if hasattr(os, _name):\n"
    "        setattr(os, _name, _keep)\n")


@pytest.fixture
def real_child_priority():
    """Chiesta da un test, lascia al figlio la sua vera chiamata per abbassare la priorità (vedi
    `_child_keeps_the_priority`)."""


@pytest.fixture(autouse=True)
def _child_keeps_the_priority(request, monkeypatch):
    if "real_child_priority" in request.fixturenames or not hasattr(whois_service, "_PARSE_CHILD"):
        return
    monkeypatch.setattr(whois_service, "_PARSE_CHILD", _KEEP_PRIORITY + "\n" + whois_service._PARSE_CHILD)


@pytest.fixture
def lookup(whois_network, monkeypatch):
    """`lookup(dominio)` interroga GET /whois sul servizio vero, libreria inclusa, con la rete finta di
    `whois_network`. Ogni chiamata è una raccolta da zero. Ritorna il corpo JSON."""
    monkeypatch.setattr(whois_service, "WHOIS_DELAY", 0.0)
    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
    monkeypatch.setattr(whois_service, "_cache", {})
    monkeypatch.setattr(whois_service, "_cache_order", [])
    api = TestClient(whois_service.app)

    def call(domain):
        whois_service._cache.clear()
        whois_service._cache_order.clear()
        response = api.get("/whois", params={"domain": domain})
        assert response.status_code == 200, response.text
        return response.json()

    return call


# ── I limiti ───────────────────────────────────────────────────────────────

_DEFAULT_LIMITS = {
    "WHOIS_LOOKUP_DEADLINE_S": 15,
    "WHOIS_IANA_MAX_BYTES": 8192,
    "WHOIS_FIRST_HOP_MAX_BYTES": 8192,
    "WHOIS_TOTAL_MAX_BYTES": 65536,
    "WHOIS_MAX_CONNECTIONS": 5,
    "WHOIS_PARSE_CPU_S": 4,
    "WHOIS_PARSE_TIMEOUT_S": 8,
    "WHOIS_PARSE_MAX_CHILDREN": 4,
}
_FIXED_ERRORS = {
    "WHOIS_PARSE_FAILED_ERROR": _FAILED_ERROR,
    "WHOIS_PARSE_BUSY_ERROR": _BUSY_ERROR,
}


class TestLimitsHaveTheirDefaults:
    """Gli altri test abbassano alcune costanti per non aspettare il tempo reale: qui si fissano i valori che
    il servizio usa quando nessuno li tocca."""

    def test_the_limits_have_the_agreed_default_values(self):
        found = {name: getattr(whois_service, name, None) for name in _DEFAULT_LIMITS}

        assert found == _DEFAULT_LIMITS, f"limiti del lookup (None = assente): {found}"

    def test_the_fixed_error_texts_are_the_agreed_ones(self):
        # Sono testi del servizio, non della libreria né del registro: chi legge `error` li riconosce.
        found = {name: getattr(whois_service, name, None) for name in _FIXED_ERRORS}

        assert found == _FIXED_ERRORS, f"testi fissi di `error` (None = assente): {found}"


# ── La rete ha un budget ───────────────────────────────────────────────────

# Picco di memoria allocata durante una richiesta con una risposta enorme (con un riscaldamento): con i tetti
# di lettura sono poche centinaia di KB; una risposta tenuta per intero (e copiata dal ciclo di lettura) ne
# vale più del doppio.
_MEMORY_LIMIT = 700 * 1024

# Tolleranza sui tetti di lettura: un blocco di `recv` della libreria.
_RECV_CHUNK = 4096
_REPLY_SIZES = [
    pytest.param("equals_xxx_referral_loop_short_replies", id="short-replies"),
    pytest.param("equals_xxx_referral_loop_long_replies", id="long-replies"),
]


class TestNetworkIsBounded:
    """I tetti di byte valgono per connessione e per il lookup intero, e un rinvio che si ripete è interrotto.
    Oltre il tetto si smette di leggere: ciò che è stato letto resta il testo da interpretare."""

    @pytest.mark.parametrize("name", _REPLY_SIZES)
    def test_a_referral_loop_is_cut_at_the_connection_limit(self, name):
        run = _run(name)

        connections = len(run.net.contacted)

        assert connections == 5, (f"il registro ripete «=xxx» e il servizio si è collegato {connections} volte "
                                  f"in tutto (limite esatto 5, server radice compreso): {run.net.contacted}; "
                                  f"{run.describe()}")

    def test_the_connection_limit_counts_the_root_server_too(self):
        # Con il server radice nel conto restano 4 connessioni per il registro: contarlo fuori ne dà 5.
        run = _run("equals_xxx_referral_loop_short_replies")

        registry_connections = run.net.connections_to(REGISTRY)

        assert registry_connections == 4, (f"il registro ha avuto {registry_connections} connessioni (attese 4 = "
                                           f"limite 5 meno quella al server radice): {run.net.contacted}")

    @pytest.mark.parametrize("name", _REPLY_SIZES)
    def test_a_referral_loop_does_not_end_in_a_recursion_error(self, name):
        run = _run(name)

        error = run.body["error"]

        assert isinstance(error, str) and error.strip(), f"precondizione: {run.describe()}"
        assert "recursion" not in error.lower(), f"il rinvio senza fine finisce in: {error!r}"

    def test_the_first_hop_is_not_read_beyond_its_cap(self):
        run = _run("first_hop_flood")

        read = run.net.delivered[REGISTRY]

        assert read <= 8192 + _RECV_CHUNK, (f"il registro ha mandato {_FLOOD} byte e il servizio ne ha letti "
                                            f"{read} (tetto del primo hop 8 KB)")

    def test_the_iana_answer_is_not_read_beyond_its_cap(self):
        run = _run("iana_flood")

        read = run.net.delivered[IANA]

        assert read <= 8192 + _RECV_CHUNK, (f"il server radice ha mandato {_FLOOD // 2} byte e il servizio ne ha "
                                            f"letti {read} (tetto del server radice 8 KB)")

    def test_a_truncated_iana_answer_still_gives_the_referral_it_starts_with(self):
        # Il troncamento tiene ciò che è stato letto: la riga «whois:» in testa vale.
        run = _run("iana_flood")

        body = run.body

        assert body["error"] is None and body["registrar"] == "Registrar Example Inc.", body

    def test_the_total_read_from_every_server_is_capped(self):
        run = _run("second_hop_flood")

        read = run.net.delivered_total

        assert read <= 65536 + _RECV_CHUNK, (f"il server del registrar ha mandato {_FLOOD // 2} byte e il "
                                             f"servizio ne ha letti {read} in tutto (tetto totale 64 KB): "
                                             f"{run.net.delivered}")

    def test_a_huge_response_does_not_fill_the_memory(self):
        run = _run("first_hop_flood")

        peak = run.peak_memory

        assert peak <= _MEMORY_LIMIT, (f"con una risposta di {_FLOOD} byte il servizio ha allocato fino a "
                                       f"{peak / 1024 / 1024:.1f} MB (limite {_MEMORY_LIMIT / 1024 / 1024:.1f} MB)")


class TestEachConnectionHasItsOwnByteCap:
    """Server radice e registro hanno tetti di byte propri, e il secondo hop nessuno (vale solo il totale)."""

    def test_the_root_server_answer_is_read_up_to_its_own_cap(self):
        run = _run("different_byte_caps_per_connection")

        read = run.net.delivered[IANA]

        assert read <= _IANA_CAP + _RECV_CHUNK, (f"il server radice è stato letto per {read} byte "
                                                 f"(tetto {_IANA_CAP}): {run.net.delivered}")

    def test_the_registry_answer_is_read_up_to_the_first_hop_cap(self):
        run = _run("different_byte_caps_per_connection")

        read = run.net.delivered[REGISTRY]

        assert _FIRST_HOP_CAP - _RECV_CHUNK < read <= _FIRST_HOP_CAP + _RECV_CHUNK, (
            f"il registro è stato letto per {read} byte (tetto {_FIRST_HOP_CAP}): {run.net.delivered}")

    def test_the_second_hop_is_not_held_to_the_first_hop_cap(self):
        run = _run("different_byte_caps_per_connection")

        read = run.net.delivered[REGISTRAR]

        assert read > _FIRST_HOP_CAP + _RECV_CHUNK, (f"il registrar è stato letto per {read} byte, quanti ne "
                                                     f"darebbe il tetto del registro: {run.net.delivered}")


class TestTotalDeadline:
    """Un server che manda un byte alla volta non fa scadere il timeout della singola operazione (10 s):
    la richiesta finisce solo se il lookup, nel suo insieme, ha una scadenza. La scadenza è abbassata a 0,6 s."""

    def test_a_server_that_drips_cannot_hold_the_request_beyond_the_total_deadline(self):
        run = _run("dripping_server")
        limit = _DRIP_DEADLINE + 2.0

        assert run.done and run.elapsed <= limit, (
            f"un server che manda un byte ogni mezzo secondo tiene la richiesta oltre {limit} s con la scadenza "
            f"totale a {_DRIP_DEADLINE} s: {run.describe()}")

    def test_a_request_ended_by_the_deadline_is_a_collection_error(self):
        # Non ha letto alcun campo: scadere non è un'osservazione.
        run = _run("dripping_server")
        assert run.done and run.elapsed <= _DRIP_DEADLINE + 2.0, f"precondizione: {run.describe()}"

        body = run.body

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _shape(body) == _empty_shape(COM), body

    def test_every_connection_is_opened_with_a_timeout_within_the_time_left_to_the_lookup(self):
        # Il `connect` è la prima operazione di una connessione: con il timeout della libreria (10 s) o senza,
        # un registro che non risponde al SYN terrebbe il lookup oltre la sua scadenza (qui 2 s).
        net = _RecordingNet()
        net.serve(REGISTRY, _com_registry(None))

        _perform(net, COM, wait=12, limits={"WHOIS_LOOKUP_DEADLINE_S": 2})

        assert len(net.timeouts_at_connect) == 2, f"precondizione, connessioni: {net.timeouts_at_connect}"
        unbounded = [(host, timeout) for host, timeout in net.timeouts_at_connect
                     if timeout is None or not 0 < timeout <= 2]
        assert not unbounded, f"timeout in vigore al connect fuori da (0, 2] s: {unbounded}"

    def test_a_silent_server_is_cut_at_the_time_left_not_at_the_operation_timeout(self):
        # Il timeout che la libreria chiede per ogni operazione (10 s) va ridotto al tempo che resta al lookup:
        # un registro che tace 5 s, con il lookup a 0,2 s, deve essere interrotto a 0,2 s e non lasciato parlare.
        net = _Net()
        net.serve(REGISTRY, _silent_then(5.0, _com_registry(None)))

        run = _perform(net, COM, wait=12, limits={"WHOIS_LOOKUP_DEADLINE_S": 0.2})

        assert run.done and run.elapsed <= 2.0, (
            f"il registro tace 5 s con la scadenza del lookup a 0,2 s (timeout per operazione 10 s): {run.describe()}")

    def test_the_deadline_is_shared_by_all_the_connections_of_a_lookup(self):
        # Ogni server risponde dopo 0,15 s; la scadenza di 0,35 s copre due connessioni ma non la terza. Con una
        # scadenza per connessione il registrar risponderebbe e il registrante sarebbe leggibile.
        net = _Net()
        net.serve(IANA, _silent_then(0.15, f"refer: x\n\nwhois:        {REGISTRY}\n"))
        net.serve(REGISTRY, _silent_then(0.15, _com_registry(REGISTRAR)))
        net.serve(REGISTRAR, _silent_then(0.15, _thick_registrar()))

        run = _perform(net, COM, wait=12, limits={"WHOIS_LOOKUP_DEADLINE_S": 0.35})

        assert run.body["registrant"]["name"] is None, (
            f"il registrar ha risposto oltre la scadenza totale del lookup: {_observed(run.body)}")


# ── Una risposta ostile non ferma il processo ──────────────────────────────

# Quanto costa una risposta ostile si misura in CPU consumata (processo di test e figli), non in secondi di
# parete: con altri processi che si contendono i core la stessa regex dura il doppio o il triplo, e un limite
# di parete passa o fallisce a seconda del carico. La CPU non cambia. I limiti stanno fra ciò che costa col
# servizio com'è e ciò che costerebbe senza la difesa che il test copre (CPU in secondi, a riposo):
# - .eu e .hk: il figlio è fermato dal limite di CPU (1 s) e consuma ~1,0; senza quel limite finisce il parsing
#   (~5,0 e ~4,4);
# - primo hop e server radice: la regex nel processo gira su 8 KB e costa ~0,4; senza il tetto di byte ~3,1 e ~2,8;
# - rinvii ripetuti e testo dell'eccezione: ~0,1 col servizio com'è; ~1,5 senza tetto sul primo hop, molto di più
#   con un figlio che non tronca il testo dell'eccezione.
# Il limite del fermo di un altro thread sta sopra ciò che una regex limitata da quel tetto tiene il GIL: è un
# tempo di parete, e sotto carico (8 processi su 4 core) arriva a ~0,9 s dai ~0,4 a riposo.
_STALL = 2.0
_CPU_BOUNDED = [
    pytest.param("eu_technical_name_followed_by_spaces", 2.0, id="eu-technical-name-and-spaces"),
    pytest.param("hk_record_without_the_expected_field", 2.0, id="hk-record-without-the-field"),
    pytest.param("spaces_after_domain_name_in_the_first_hop", 1.2, id="first-hop-spaces-after-domain-name"),
    pytest.param("spaces_after_whois_in_the_iana_answer", 1.2, id="iana-spaces-after-whois"),
    pytest.param("repeated_domain_name_lines", 0.7, id="repeated-domain-name-lines"),
    pytest.param("parser_exception_with_a_long_text", 0.7, id="parser-exception-with-a-long-text"),
]
_NOT_FROZEN = [
    pytest.param("long_line_in_the_second_hop", id="long-line-in-the-second-hop"),
    pytest.param("spaces_after_domain_name_in_the_first_hop", id="first-hop-spaces-after-domain-name"),
    pytest.param("spaces_after_whois_in_the_iana_answer", id="iana-spaces-after-whois"),
    pytest.param("repeated_domain_name_lines", id="repeated-domain-name-lines"),
    pytest.param("parser_exception_with_a_long_text", id="parser-exception-with-a-long-text"),
]


class TestHostileResponsesDoNotFreezeTheProcess:
    """Una risposta ostile costa una quantità limitata di CPU, e nel frattempo gli altri thread del processo
    (dashboard, sonde di salute, login) restano vivi."""

    @pytest.mark.parametrize("name, limit", _CPU_BOUNDED)
    def test_the_request_costs_a_bounded_amount_of_cpu(self, name, limit):
        run = _run(name)
        assert run.done, f"{name}: la richiesta non è finita: {run.describe()}"

        spent = run.cpu_self + run.cpu_children

        assert spent <= limit, (f"{name}: la richiesta ha consumato {spent:.2f} s di CPU "
                                f"(processo {run.cpu_self:.2f}, figli {run.cpu_children:.2f}; limite {limit} s)")

    @pytest.mark.parametrize("name", _NOT_FROZEN)
    def test_no_other_thread_of_the_process_is_frozen_for_long(self, name):
        run = _run(name)

        assert run.stall <= _STALL, (f"{name}: un altro thread del processo è rimasto fermo {run.stall:.2f} s "
                                     f"(limite {_STALL} s); {run.describe()}")


# ── L'esito di un parsing che non finisce, e di uno che solleva ────────────

_CHILD_STDOUT_MARKER = "raw-child-stdout-5d1f"
_CHILD_STDERR_MARKER = "raw-child-stderr-5d1f"
_RAW_FRAGMENTS = [_RAW_MARKER, _CHILD_STDOUT_MARKER, _CHILD_STDERR_MARKER, REGISTRY, IANA, "Errno", "Traceback"]


class TestOutcomeWhenTheParserCannotFinish:
    """Un parsing che muore o scade è un errore di raccolta con un testo del servizio, con la forma di un
    lookup fallito: il consumatore si fida di `error` e non deve vedere un'osservazione a metà."""

    def test_a_parser_that_cannot_finish_gives_a_collection_error(self):
        run = _run("eu_technical_name_followed_by_spaces")

        error = run.body["error"]

        assert isinstance(error, str) and error.strip(), (
            f"il parser di .eu non finisce, ma `error` è {error!r}: {_shape(run.body)}")

    def test_the_error_does_not_carry_the_registry_text_or_the_systems(self):
        run = _run("eu_technical_name_followed_by_spaces")
        error = run.body["error"]
        assert isinstance(error, str) and error.strip(), f"precondizione: {run.describe()}"

        leaked = [fragment for fragment in _RAW_FRAGMENTS if fragment in error]

        assert not leaked, f"in `error` c'è testo che non è del servizio ({leaked}): {error!r}"

    def test_a_parser_that_cannot_finish_leaves_no_partial_observation(self):
        # I campi in testa al record (registrar, name server) non devono sopravvivere: il lookup è fallito.
        run = _run("eu_technical_name_followed_by_spaces")

        assert _shape(run.body) == _empty_shape(EU), (
            f"il parser di .eu non finisce, ma la risposta porta dei campi: {_observed(run.body)}")


def _child(returncode, stdout, stderr):
    """Un doppio di `subprocess.Popen` per un figlio che finisce male: esce con `returncode` e scrive
    `stdout` e `stderr`. Accetta le chiamate di `Popen` e di `communicate` che il servizio può fare."""

    class FailingChild:
        def __init__(self, args=None, *_, **kwargs):
            self.args, self.returncode, self.pid = args, None, 0
            self.stdin = self.stdout = self.stderr = None
            self._text = bool(kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding"))

        def _out(self, value):
            return value if self._text else value.encode()

        def communicate(self, input=None, timeout=None):
            self.returncode = returncode
            return self._out(stdout), self._out(stderr)

        def wait(self, timeout=None):
            self.returncode = returncode
            return returncode

        def poll(self):
            return self.returncode

        def kill(self):
            pass

        terminate = kill

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return FailingChild


_CHILD_FAILURES = ["wall-timeout", "exit-code", "garbage-stdout"]

# Risposte del registro che il parser rifiuta con un'eccezione che porta il testo intero («No match for…»):
# oltre i 1024 caratteri, senza percorsi (la prima) o con un percorso a cavallo del 200° carattere (la seconda).
_NO_MATCH = 'No match for "ACME-TYPO.COM".\r\n'
_PLAIN_LONG_TEXT = _NO_MATCH + "registry notice " * 200
_LONG_PARSER_TEXTS = [
    pytest.param(_PLAIN_LONG_TEXT, id="plain-text"),
    pytest.param(_NO_MATCH + "x" * 140 + " /srv/lib/modules/some_module_name.py" + " tail" * 300,
                 id="path-across-the-200-character-cut"),
]


@pytest.fixture
def lookup_with_a_failing_child(lookup, whois_network, monkeypatch):
    """`run(modo)`: il registro risponde con un record leggibile, ma il figlio che lo interpreta fallisce:
    `wall-timeout` (timeout di parete di 1 ms), `exit-code` (esce con 1 e scrive sull'output e su stderr),
    `garbage-stdout` (esce con 0 e scrive testo che non è il risultato). Ritorna il corpo JSON."""

    def run(mode):
        whois_network.registry("com", _com_registry(None) + f"Remarks: {_RAW_MARKER}\r\n")
        if mode == "wall-timeout":
            monkeypatch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", 0.001, raising=False)
        else:
            stderr = f"Traceback (most recent call last): {_CHILD_STDERR_MARKER}"
            monkeypatch.setattr(whois_service.subprocess, "Popen",
                                _child(1 if mode == "exit-code" else 0, f"not json {_CHILD_STDOUT_MARKER}", stderr))
        return lookup(COM)

    return run


class TestOutcomeWhenTheChildFails:
    """Per ogni modo in cui il figlio può fallire (scade, esce con un errore, scrive ciò che non è il risultato)
    l'esito è lo stesso errore di raccolta: un testo del servizio, mai ciò che il figlio ha scritto o il
    testo della risposta, e la forma di un lookup fallito."""

    @pytest.mark.parametrize("mode", _CHILD_FAILURES)
    def test_the_error_is_the_services_own_text(self, lookup_with_a_failing_child, mode):
        body = lookup_with_a_failing_child(mode)

        error = body["error"]

        assert isinstance(error, str) and error.strip(), (
            f"{mode}: il figlio fallisce, ma `error` è {error!r}: {_observed(body)}")
        leaked = [fragment for fragment in _RAW_FRAGMENTS if fragment in error]
        assert not leaked, f"{mode}: in `error` c'è testo che non è del servizio ({leaked}): {error!r}"

    @pytest.mark.parametrize("mode", _CHILD_FAILURES)
    def test_the_response_has_the_shape_of_a_failed_lookup(self, lookup_with_a_failing_child, mode):
        body = lookup_with_a_failing_child(mode)

        assert _shape(body) == _empty_shape(COM), (
            f"{mode}: il figlio fallisce, ma la risposta porta dei campi: {_observed(body)}")


def _hung_child(killed):
    """Un doppio di `Popen` per un figlio che non risponde mai: `communicate` scade sempre e ogni `kill` si registra."""

    class HungChild:
        def __init__(self, *_, **__):
            self.returncode = None

        def communicate(self, input=None, timeout=None):
            raise subprocess.TimeoutExpired("child", timeout)

        def kill(self):
            killed.append(True)

        def wait(self, timeout=None):
            self.returncode = -9
            return -9

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return HungChild


class TestTheChildThatCannotRunIsContained:
    """Il testo fisso vale anche per la scadenza di parete e per l'avvio fallito (altrimenti `error` porterebbe
    l'eccezione di `subprocess`: interprete, argomenti, sorgente del figlio), e un figlio scaduto è ucciso."""

    def test_a_wall_timeout_gives_the_fixed_error_text(self, lookup, whois_network, monkeypatch):
        whois_network.registry("com", _com_registry(None))
        monkeypatch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", 0.001, raising=False)

        body = lookup(COM)

        assert body["error"] == whois_service.WHOIS_PARSE_FAILED_ERROR, body["error"]

    def test_a_child_that_cannot_start_gives_the_fixed_error_text(self, lookup, whois_network, monkeypatch):
        whois_network.registry("com", _com_registry(None))
        monkeypatch.setattr(sys, "executable", "/nonexistent/python")

        body = lookup(COM)

        assert body["error"] == whois_service.WHOIS_PARSE_FAILED_ERROR, body["error"]

    def test_the_child_is_killed_when_the_wall_timeout_expires(self, lookup, whois_network, monkeypatch):
        killed = []
        monkeypatch.setattr(whois_service.subprocess, "Popen", _hung_child(killed))
        whois_network.registry("com", _com_registry(None))

        lookup(COM)

        assert killed, "il figlio ha superato il timeout di parete e non è stato ucciso"


class TestOutcomeWhenTheParserRaises:
    """Un'eccezione del parser con un testo proprio resta un errore con quel testo: sanificato e troncato come
    ogni altro errore del servizio (200 caratteri più «...»), senza che `sanitize_error` lavori sul testo
    intero della risposta."""

    def test_the_error_is_no_longer_than_a_sanitized_long_text(self):
        run = _run("parser_exception_with_a_long_text")
        limit = len(sanitize_error(Exception("x" * 1000)))

        error = run.body["error"]

        assert isinstance(error, str) and error.strip(), f"precondizione: {run.describe()}"
        assert len(error) <= limit, (f"`error` è di {len(error)} caratteri, un testo lungo sanificato ne dà "
                                     f"{limit}")

    def test_a_parser_exception_keeps_its_own_text(self, lookup, whois_network):
        # Non è un parser che muore: il testo dell'eccezione arriva nell'errore, non un testo fisso.
        whois_network.registry("com", _NOT_REGISTERED_COM)

        body = lookup(COM)

        assert isinstance(body["error"], str) and 'No match for "ACME-TYPO.COM"' in body["error"], body
        assert _shape(body) == _empty_shape(COM), body

    @pytest.mark.parametrize("text", _LONG_PARSER_TEXTS)
    def test_a_long_parser_exception_is_sanitized_as_a_whole(self, lookup, whois_network, text):
        # L'eccezione porta il testo intero della risposta. Quanto ne passa il figlio basta perché
        # `sanitize_error` ridia lo stesso errore che darebbe sul testo intero: redatto e poi troncato a 200
        # caratteri con «...». Il caso con un percorso a cavallo del 200° carattere lo distingue da un taglio
        # troppo corto, che lascerebbe un percorso a metà.
        whois_network.registry("com", text)

        body = lookup(COM)

        assert body["error"] == sanitize_error(Exception(text)), body["error"]

    def test_the_text_handed_to_sanitize_error_is_at_most_1024_characters(self, lookup, whois_network, monkeypatch):
        # Il tetto sta nel figlio, prima che `sanitize_error` giri nel processo del servizio.
        seen = []

        def spy(error):
            seen.append(str(error))
            return sanitize_error(error)

        monkeypatch.setattr(whois_service, "sanitize_error", spy)
        whois_network.registry("com", _PLAIN_LONG_TEXT)

        lookup(COM)

        assert seen and max(len(text) for text in seen) <= 1024, [len(text) for text in seen]


# ── Un troncamento è un'osservazione, non un errore ────────────────────────

class TestTruncationKeepsTheFieldsAlreadyRead:
    """Oltre il tetto si smette di leggere e si tiene il testo letto: i campi nei primi KB restano."""

    def test_a_first_hop_longer_than_the_cap_keeps_the_fields_at_its_start(self, lookup, whois_network):
        whois_network.registry("com", _com_registry(None) + _PADDING_LINE * 1_300)

        body = lookup(COM)

        assert body["error"] is None, f"un registro che manda 100 KB dà un errore: {body}"
        assert body["registrar"] == "Registrar Example Inc." and body["nameservers"] == [
            "ns1.acme-typo.com", "ns2.acme-typo.com"], body

    def test_a_second_hop_longer_than_the_cap_keeps_the_fields_at_its_start(self, lookup, whois_network):
        whois_network.registry("com", _com_registry(REGISTRAR))
        whois_network.registrar(_REGISTRANT_VISIBLE + _PADDING_LINE * 1_300)

        body = lookup(COM)

        assert body["error"] is None, f"un registrar che manda 100 KB dà un errore: {body}"
        assert body["registrant"]["name"] == "Reg Name" and body["privacy_protected"] is False, body


# ── Le risposte leggibili producono gli stessi campi ───────────────────────

def _comparable(body):
    """Il corpo senza l'istante e senza `age_days`, che dipendono dal momento della richiesta."""
    return {key: value for key, value in body.items() if key not in ("timestamp", "age_days")}


def _shape(body):
    """La risposta senza l'istante e senza `error`: ciò che resta quando non si è osservato nulla."""
    return {key: value for key, value in body.items() if key not in ("timestamp", "error")}


def _observed(body):
    """I soli campi valorizzati di una risposta: per i messaggi di errore."""
    keys = ("registrar", "creation_date", "expiration_date", "updated_date", "status", "nameservers")
    found = {key: body[key] for key in keys if body[key]}
    found.update({f"registrant.{key}": value for key, value in body["registrant"].items() if value})
    return found


def _empty_shape(domain):
    return {"domain": domain, "registrar": None, "creation_date": None, "expiration_date": None,
            "updated_date": None, "status": [], "nameservers": [],
            "registrant": {"name": None, "org": None, "country": None, "email": None},
            "privacy_protected": False, "dnssec": False, "age_days": None}


def _expected(domain, **fields):
    body = {"domain": domain, "registrar": None, "creation_date": None, "expiration_date": None,
            "updated_date": None, "status": [], "nameservers": [], "privacy_protected": False,
            "dnssec": False, "error": None,
            "registrant": {"name": None, "org": None, "country": None, "email": None}}
    body.update(fields)
    return body


def _serve_com_thin(network):
    network.registry("com", _com_registry(None))


def _serve_com_two_hops(network):
    network.registry("com", _com_registry(REGISTRAR))
    network.registrar(_thick_registrar())


def _serve_de(network):
    network.registry("de", _DE_RECORD)


def _serve_it(network):
    network.registry("it", _IT_RECORD)


def _serve_eu(network):
    network.registry("eu", _EU_RECORD)


def _serve_org_two_hops(network):
    network.registry("org", _ORG_RECORD)
    network.registrar(_thick_registrar())


# Il corpo atteso di ogni risposta di dimensione e forma tipiche (record sottile, a due hop, con testo
# legale di ~1,7 KB su una riga, TLD con parser dedicato). Il `.eu` mette in un solo elemento il blocco dei
# name server e quanto lo segue: è il comportamento del parser della libreria pinnata.
_READABLE = [
    pytest.param(COM, _serve_com_thin, _expected(
        COM, registrar="Registrar Example Inc.", creation_date="2020-01-01T00:00:00",
        expiration_date="2027-01-01T00:00:00", updated_date="2026-05-01T10:00:00", status=[_COM_STATUS],
        nameservers=["ns1.acme-typo.com", "ns2.acme-typo.com"], privacy_protected=True,
        registrant={"name": None, "org": None, "country": None, "email": "abuse@registrar.example"}),
        id="com-thin-record"),
    pytest.param(COM, _serve_com_two_hops, _expected(
        COM, registrar="Registrar Example Inc.", creation_date="2020-01-01T00:00:00",
        expiration_date="2027-01-01T00:00:00", updated_date="2026-05-01T10:00:00",
        status=[_COM_STATUS, "clientTransferProhibited"],
        nameservers=["ns1.acme-typo.com", "ns2.acme-typo.com"], privacy_protected=False,
        registrant={"name": "Reg Name", "org": "Reg Name Srl", "country": "IT",
                    "email": "abuse@registrar.example"}),
        id="com-two-hops-with-legal-text"),
    pytest.param(DE, _serve_de, _expected(
        DE, updated_date="2026-05-01T10:00:00+02:00", status=["connect"],
        nameservers=["ns1.acme-typo.de", "ns2.acme-typo.de"], privacy_protected=True),
        id="de"),
    pytest.param(IT, _serve_it, _expected(
        IT, registrar="Registrar Example", creation_date="2020-01-01T00:00:00",
        expiration_date="2027-01-01T00:00:00", updated_date="2026-05-01T10:00:00", status=["ok"],
        nameservers=["ns1.acme-typo.it\n  ns2.acme-typo.it"], privacy_protected=True),
        id="it"),
    pytest.param(EU, _serve_eu, _expected(
        EU, registrar="Registrar Example", privacy_protected=True,
        nameservers=["ns1.acme-typo.eu\n        ns2.acme-typo.eu\n\nkeys:\n        flags:ksk protocol:3 "
                     "algorithm:ecdsap256sha256 pubkey:" + "a" * 88
                     + "\n\nplease visit www.registry.example for more info."]),
        id="eu"),
    pytest.param(ORG, _serve_org_two_hops, _expected(
        ORG, registrar="Registrar Example Inc.", creation_date="2020-01-01T00:00:00",
        expiration_date="2027-01-01T00:00:00", updated_date="2026-05-01T10:00:00",
        status=["clientTransferProhibited"],
        nameservers=["ns1.acme-typo.org", "ns2.acme-typo.org", "ns1.acme-typo.com", "ns2.acme-typo.com"],
        privacy_protected=False,
        registrant={"name": "Reg Name", "org": "Reg Name Srl", "country": "IT", "email": "reg@acme-typo.example"}),
        id="org-two-hops"),
]


class TestReadableResponsesAreReadFieldByField:
    """Controllo: le risposte reali, di dimensione e forma tipiche, danno gli stessi campi con il budget di
    rete e il parsing in un processo figlio (date comprese, con o senza fuso)."""

    @pytest.mark.parametrize("domain, serve, expected", _READABLE)
    def test_the_body_is_the_expected_one(self, lookup, whois_network, domain, serve, expected):
        serve(whois_network)

        body = lookup(domain)

        assert _comparable(body) == expected, body

    def test_a_domain_the_registry_does_not_know_is_an_error(self, lookup, whois_network):
        whois_network.registry("com", _NOT_REGISTERED_COM)

        body = lookup(COM)

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _shape(body) == _empty_shape(COM), body

    def test_an_unreachable_iana_is_an_error(self, lookup, whois_network):
        whois_network.iana(whois_network.REFUSED)

        body = lookup(COM)

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _shape(body) == _empty_shape(COM), body


# ── Il figlio vero, visto da fuori ─────────────────────────────────────────
#
# Ambiente, priorità e limiti del figlio, e quanti figli vivono insieme, non si leggono dall'esito di un
# lookup: si vedono solo guardando il processo. Un sottotipo di `Popen` lancia il figlio vero (il lookup resta
# quello vero) e, prima di passargli l'input, lo osserva da `/proc`. Il figlio si restringe prima di leggere lo
# stdin, quindi tenerlo in attesa dell'input finché ha cambiato aspetto vuol dire guardarlo già ristretto: si
# aspetta una condizione (con un tetto di tempo), non un intervallo fisso.

_REAL_POPEN = subprocess.Popen    # preso all'importazione: i sottotipi lo estendono, i test lo sostituiscono
_WATCH_PATIENCE = 5.0             # quanto si aspetta che il figlio si restringa; oltre, lo si guarda com'è
_CORE_ROW, _CPU_ROW = "Max core file size", "Max cpu time"
_LIMIT_ROW = re.compile(r"^(Max .+?)\s{2,}(\S+)\s+(\S+)(?:\s+\S+)?$")


def _proc_limits(pid):
    """`/proc/<pid>/limits` come {nome: (soft, hard)}, con `None` per «unlimited»."""
    limits = {}
    with open(f"/proc/{pid}/limits") as source:
        for row in source:
            found = _LIMIT_ROW.match(row.strip())
            if found:
                name, soft, hard = found.groups()
                limits[name] = tuple(None if value == "unlimited" else int(value) for value in (soft, hard))
    return limits


def _proc_environ(pid):
    """L'ambiente con cui il processo è partito (`/proc/<pid>/environ`)."""
    with open(f"/proc/{pid}/environ", "rb") as source:
        pairs = (item.split(b"=", 1) for item in source.read().split(b"\0") if item)
        return {os.fsdecode(name): os.fsdecode(value) for name, value in pairs}


def _arguments_published(pid):
    """Subito dopo l'exec il kernel non ha ancora pubblicato argomenti e ambiente del programma avviato, e
    `/proc/<pid>/environ` si legge vuoto (circa 1 volta su 60): `cmdline` lo precede di poco e dice quando
    l'ambiente è leggibile. Un processo già morto non si aspetta."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as source:
            return bool(source.read(1))
    except OSError:
        return True


class _ChildSeen:
    """Ciò che si vede dall'esterno di un figlio vivo: ambiente, priorità, limiti (`None` se è già morto). Il
    `repr` porta i nomi delle variabili e mai i valori: pytest lo stampa nei messaggi di errore, e l'ambiente
    del processo di test può contenere credenziali che non devono finire in un log."""

    def __init__(self, environ=None, nice=None, limits=None):
        self.environ, self.nice, self.limits = environ, nice, limits

    def __repr__(self):
        names = None if self.environ is None else sorted(self.environ)
        return f"<figlio nice={self.nice} variabili={names} limiti={self.limits}>"


def _look_at(pid):
    try:
        return _ChildSeen(_proc_environ(pid), os.getpriority(os.PRIO_PROCESS, pid), _proc_limits(pid))
    except OSError:
        return _ChildSeen()


class _ChildWatch:
    """Osserva ogni figlio vero prima che riceva l'input. Se `ready` è dato, aspetta (al più `_WATCH_PATIENCE`)
    che la condizione sull'osservazione diventi vera: il figlio ha finito di restringersi."""

    def __init__(self, ready=None):
        self.ready, self.seen = ready, []

    def look(self, pid):
        give_up = time.monotonic() + _WATCH_PATIENCE
        while not _arguments_published(pid) and time.monotonic() < give_up:
            time.sleep(0.001)
        seen = _look_at(pid)
        while self.ready is not None and not self.ready(seen) and time.monotonic() < give_up:
            time.sleep(0.005)
            seen = _look_at(pid)
        return seen

    def popen(self):
        watch = self

        class WatchedPopen(_REAL_POPEN):
            def communicate(self, input=None, timeout=None):
                watch.seen.append(watch.look(self.pid))
                return super().communicate(input=input, timeout=timeout)

        return WatchedPopen


@pytest.fixture
def watched_lookup(lookup, whois_network, monkeypatch):
    """`watched(ready=None)`: un lookup .com con il figlio vero osservato. Ritorna il corpo e l'osservazione
    dell'unico figlio che il lookup lancia."""

    def watched(ready=None):
        whois_network.registry("com", _com_registry(None))
        watch = _ChildWatch(ready)
        monkeypatch.setattr(whois_service.subprocess, "Popen", watch.popen())
        body = lookup(COM)
        assert len(watch.seen) == 1, f"un lookup deve lanciare un solo figlio, ne ha lanciati {len(watch.seen)}"
        return body, watch.seen[0]

    return watched


# ── Il figlio non eredita l'ambiente del servizio ──────────────────────────

# Ciò che il servizio ha di riservato (credenziali, chiavi) sta nell'ambiente del suo processo: il figlio
# interpreta testo di terzi e non deve vederlo in `/proc/<pid>/environ`. Le variabili sentinella stanno per
# quelle: il test non dipende dai loro nomi veri ma dal fatto che nessuna variabile fuori lista arrivi.
_ENV_ALLOW_LIST = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "LD_LIBRARY_PATH"}
_SENTINELS = {"SEC35_SENTINEL_A": "sentinel-a-5d1f", "SEC35_SENTINEL_B": "sentinel-b-5d1f",
              "SEC35_SENTINEL_C": "sentinel-c-5d1f"}


# I nomi (solo i nomi) delle credenziali che i file compose passano al servizio. I valori sono sentinelle finte.
# Una lista bianca estesa con uno di questi nomi non la vede il test sulle sentinelle neutre, che usa nomi propri.
_COMPOSE_CREDENTIALS = ("ADMIN_PASSWORD", "SERVICE_TOKEN", "CASE_INGEST_TOKEN", "VT_API_KEY", "OTX_API_KEY",
                        "ST_API_KEY")


class TestChildEnvironment:
    """Il figlio riceve dall'ambiente solo `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `LD_LIBRARY_PATH`, e solo
    quelle che il servizio ha."""

    def test_none_of_the_credentials_of_the_compose_files_reaches_the_child(self, watched_lookup, monkeypatch):
        for number, name in enumerate(_COMPOSE_CREDENTIALS):
            monkeypatch.setenv(name, f"sentinel-{number}-5d1f")

        _, child = watched_lookup()

        assert child.environ is not None, "il figlio è morto prima di poterlo osservare"
        leaked = [name for name in _COMPOSE_CREDENTIALS if name in child.environ]
        assert not leaked, f"il figlio ha ricevuto credenziali del servizio (nomi): {leaked}"

    def test_the_child_does_not_inherit_the_environment_of_the_service(self, watched_lookup, monkeypatch):
        for name, value in _SENTINELS.items():
            monkeypatch.setenv(name, value)

        _, child = watched_lookup()

        assert child.environ is not None, "il figlio è morto prima di poterlo osservare"
        extra = sorted(set(child.environ) - _ENV_ALLOW_LIST)
        assert not extra, f"il figlio ha ricevuto variabili fuori dalla lista bianca (nomi): {extra}"

    def test_the_allow_listed_variables_reach_the_child_unchanged(self, watched_lookup, monkeypatch):
        expected = {"PATH": os.environ.get("PATH", "") + os.pathsep + "/sec35-no-such-bin", "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8", "LC_CTYPE": "C.UTF-8", "TZ": "UTC",
                    "LD_LIBRARY_PATH": "/sec35-no-such-lib"}
        for name, value in expected.items():
            monkeypatch.setenv(name, value)

        _, child = watched_lookup()

        assert child.environ is not None, "il figlio è morto prima di poterlo osservare"
        received = {name: child.environ.get(name) for name in expected}
        assert received == expected

    def test_an_allow_listed_variable_the_service_does_not_have_is_not_invented(self, watched_lookup, monkeypatch):
        absent = sorted(_ENV_ALLOW_LIST - {"PATH"})
        for name in absent:
            monkeypatch.delenv(name, raising=False)

        _, child = watched_lookup()

        assert child.environ is not None, "il figlio è morto prima di poterlo osservare"
        invented = {name: child.environ[name] for name in absent if name in child.environ}
        assert not invented, f"il figlio ha variabili che il servizio non ha: {invented}"


# ── Il figlio è ristretto prima di leggere l'input ─────────────────────────

@contextlib.contextmanager
def _core_dumps_allowed():
    """Alza il limite soft dei core del processo di test (se quello rigido lo permette): un figlio che non lo
    azzera lo erediterebbe, e con 0 già ereditato la mancanza non si vedrebbe."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    wanted = 1 << 20 if hard == resource.RLIM_INFINITY else min(hard, 1 << 20)
    resource.setrlimit(resource.RLIMIT_CORE, (wanted, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_CORE, (soft, hard))


class TestChildIsRestrained:
    """Il figlio interpreta testo ostile: lo fa con meno priorità del servizio, senza poter scrivere un core con
    quel testo e con un limite di CPU. Tutto prima di leggere l'input."""

    def test_the_child_runs_at_a_lower_priority_than_the_service(self, watched_lookup, real_child_priority):
        expected = min(os.getpriority(os.PRIO_PROCESS, 0) + 10, 19)

        _, child = watched_lookup(ready=lambda seen: seen.nice == expected)

        assert child.nice == expected, f"priorità (nice) del figlio {child.nice}, attesa {expected}"

    def test_the_child_cannot_write_a_core_file(self, watched_lookup):
        with _core_dumps_allowed():
            _, child = watched_lookup(ready=lambda seen: (seen.limits or {}).get(_CORE_ROW) == (0, 0))

        assert (child.limits or {}).get(_CORE_ROW) == (0, 0), f"limite dei core del figlio: {child.limits}"

    def test_the_child_cpu_limit_is_the_configured_one(self, watched_lookup, monkeypatch):
        # Soft = il valore configurato (letto a ogni lookup); il limite rigido è finito e vicino, così il figlio
        # muore anche se ignorasse il segnale del soft.
        monkeypatch.setattr(whois_service, "WHOIS_PARSE_CPU_S", 3, raising=False)

        _, child = watched_lookup(ready=lambda seen: (seen.limits or {}).get(_CPU_ROW, (None,))[0] == 3)

        soft, hard = (child.limits or {}).get(_CPU_ROW, (None, None))
        assert soft == 3 and hard is not None and 3 <= hard <= 5, f"limite di CPU del figlio (soft, hard): {soft, hard}"

    def test_the_child_does_not_import_modules_from_the_working_directory(self, lookup, whois_network, monkeypatch,
                                                                         tmp_path):
        # Il figlio parte con `-c`: senza `-I` la directory corrente sarebbe la prima di `sys.path` e un `json.py`
        # lì dentro verrebbe eseguito al posto di quello della libreria standard.
        marker = tmp_path / "hostile-module-was-imported"
        (tmp_path / "json.py").write_text(f"open({str(marker)!r}, 'w').close()\nraise ImportError('hostile')\n")
        whois_network.registry("com", _com_registry(None))
        monkeypatch.chdir(tmp_path)

        body = lookup(COM)

        assert not marker.exists(), f"il figlio ha importato un modulo dalla directory corrente: {body['error']!r}"


# ── Quando il figlio non riesce a restringersi ─────────────────────────────

def _inject_into_the_child(monkeypatch, code):
    """Antepone `code` al programma del figlio: un guasto iniettato nel solo figlio, prima che chiami ciò che
    il programma chiama. Ogni iniezione scrive un file spia quando il guasto scatta, così il test sa che ha agito.
    I rifiuti coprono tutti i modi di imporre lo stesso effetto (`os.nice`, `os.setpriority`, `resource.setrlimit`,
    `resource.prlimit`...), perché il test non dipenda da quale dei due il figlio sceglie."""
    monkeypatch.setattr(whois_service, "_PARSE_CHILD", code + "\n" + whois_service._PARSE_CHILD)


class TestChildRestraintFailures:
    """La priorità è un'attenuazione: se il sistema la rifiuta (es. capacità o limiti del contenitore) il lookup
    deve comunque riuscire, altrimenti ogni lookup fallirebbe, con l'errore in cache. I limiti di core e di CPU
    sono invece la difesa: se non si possono imporre il figlio non interpreta il testo."""

    def test_a_refused_priority_change_does_not_fail_the_lookup(self, lookup, whois_network, monkeypatch, tmp_path,
                                                                real_child_priority):
        spy = tmp_path / "priority-was-refused"
        _inject_into_the_child(monkeypatch, (
            "import os\n"
            "def _refused(*_, **__):\n"
            f"    open({str(spy)!r}, 'w').close()\n"
            "    raise PermissionError(1, 'Operation not permitted')\n"
            f"for _name in {_PRIORITY_CALLS!r}:\n"
            "    if hasattr(os, _name):\n"
            "        setattr(os, _name, _refused)\n"))
        whois_network.registry("com", _com_registry(None))

        body = lookup(COM)

        assert spy.exists(), "precondizione: l'iniezione non ha agito, il figlio non ha abbassato la priorità"
        assert body["error"] is None and body["registrar"] == "Registrar Example Inc.", body["error"]

    @pytest.mark.parametrize("limit", ["RLIMIT_CORE", "RLIMIT_CPU"])
    def test_a_refused_resource_limit_fails_the_lookup_with_the_fixed_text(
            self, lookup, whois_network, monkeypatch, tmp_path, limit):
        spy = tmp_path / "limit-was-refused"
        _inject_into_the_child(monkeypatch, (
            "import resource\n"
            "def _refuse():\n"
            f"    open({str(spy)!r}, 'w').close()\n"
            "    raise OSError(1, 'Operation not permitted')\n"
            "_real_setrlimit = resource.setrlimit\n"
            "def _setrlimit(which, limits):\n"
            f"    if which == resource.{limit}:\n"
            "        _refuse()\n"
            "    return _real_setrlimit(which, limits)\n"
            "resource.setrlimit = _setrlimit\n"
            "if hasattr(resource, 'prlimit'):\n"
            "    _real_prlimit = resource.prlimit\n"
            "    def _prlimit(pid, which, limits=None):\n"
            f"        if which == resource.{limit} and limits is not None:\n"
            "            _refuse()\n"
            "        return _real_prlimit(pid, which) if limits is None else _real_prlimit(pid, which, limits)\n"
            "    resource.prlimit = _prlimit\n"))
        whois_network.registry("com", _com_registry(None))

        body = lookup(COM)

        assert spy.exists(), f"precondizione: l'iniezione non ha agito, il figlio non ha imposto {limit}"
        assert body["error"] == _FAILED_ERROR, body["error"]
        assert _shape(body) == _empty_shape(COM), _observed(body)


# ── Al più N figli vivi insieme ────────────────────────────────────────────

_GATE_PATIENCE = 30    # un figlio tenuto dal cancello lo lascia comunque andare: nessun test resta appeso
_SEAT_PATIENCE = 20    # attesa del posto nei test in cui nessuno deve restare senza


def _wait_until(condition, patience):
    """Vero appena `condition()` lo è, falso se non lo diventa entro `patience` secondi (sondaggio da 5 ms)."""
    end = time.monotonic() + patience
    while not condition():
        if time.monotonic() >= end:
            return False
        time.sleep(0.005)
    return True


class _ChildGate:
    """Tiene la contabilità dei figli veri: quanti ne sono nati e quanti vivi insieme al massimo (un figlio è vivo
    dalla nascita a quando il servizio l'ha atteso). I primi `hold` restano fermi prima di ricevere l'input finché
    il test apre il cancello, e occupano il loro posto; gli altri passano."""

    def __init__(self, hold):
        self.hold, self.created, self.alive, self.peak, self.held = hold, 0, 0, 0, 0
        self.changed = threading.Condition()
        self.opened = threading.Event()

    def wait_held(self, count, patience):
        with self.changed:
            return self.changed.wait_for(lambda: self.held >= count, patience)

    def wait_created_beyond(self, count, patience):
        with self.changed:
            return self.changed.wait_for(lambda: self.created > count, patience)

    def _ended(self, child):
        with self.changed:
            if not child.ended:
                child.ended = True
                self.alive -= 1
                self.changed.notify_all()

    def popen(self):
        gate = self

        class GatedPopen(_REAL_POPEN):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.ended = False
                with gate.changed:
                    gate.created += 1
                    gate.alive += 1
                    gate.peak = max(gate.peak, gate.alive)
                    self.number = gate.created
                    gate.changed.notify_all()

            def communicate(self, input=None, timeout=None):
                if self.number <= gate.hold:
                    with gate.changed:
                        gate.held += 1
                        gate.changed.notify_all()
                    gate.opened.wait(_GATE_PATIENCE)
                return super().communicate(input=input, timeout=timeout)

            def wait(self, timeout=None):
                code = super().wait(timeout=timeout)
                gate._ended(self)
                return code

        return GatedPopen


def _over_a_gate(seats, parse_timeout, hold, scenario):
    """Il servizio con `seats` posti per i figli, la rete finta e i primi `hold` figli tenuti dal cancello.
    `scenario(gate, net, start)` avvia le richieste con `start(dominio)` e osserva ciò che serve; alla fine il
    cancello si apre e tutte le richieste finiscono (nessun thread resta appeso al test)."""
    net = _Net()
    net.serve(REGISTRY, _com_registry(None))
    gate = _ChildGate(hold)
    runs = []

    def start(domain):
        run = _Run(net)
        runs.append(run)
        run.start(domain)
        return run

    limits = {"WHOIS_PARSE_MAX_CHILDREN": seats, "WHOIS_PARSE_TIMEOUT_S": parse_timeout}
    with _service_over(net, limits, popen=gate.popen()):
        try:
            outcome = scenario(gate, net, start)
        finally:
            gate.opened.set()
            for run in runs:
                run.wait(20)
    return SimpleNamespace(gate=gate, runs=runs, outcome=outcome)


def _answer(run):
    """L'`error` di una richiesta, o come è finita se non ha risposto: per i messaggi dei test."""
    return run.describe() if run.body is None else run.body["error"]


@functools.cache
def _crowd():
    """4 richieste su 2 posti: i primi 2 figli restano fermi, le altre 2 richieste devono aspettare."""

    lookups = 4

    def scenario(gate, net, start):
        for number in range(lookups):
            start(f"acme-typo-{number}.com")
        reached = gate.wait_held(2, patience=10)
        # Le richieste in più arrivano al punto in cui un figlio parte (o aspetta il posto): due connessioni
        # ciascuna, server radice e registro. Un servizio senza tetto avvia i figli in più subito e questa
        # finestra si chiude presto; con il tetto passa tutta, ed è l'unica attesa a vuoto del test.
        _wait_until(lambda: len(net.contacted) >= 2 * lookups, patience=10)
        gate.wait_created_beyond(2, patience=0.3)
        return reached

    return _over_a_gate(seats=2, parse_timeout=_SEAT_PATIENCE, hold=2, scenario=scenario)


class TestChildrenAreCapped:
    """Al più `WHOIS_PARSE_MAX_CHILDREN` figli vivi insieme, anche con più richieste di quanti posti ci sono: le
    altre aspettano che se ne liberi uno. Il limite si legge a ogni lookup (qui è 2, negli altri test 1)."""

    def test_no_more_children_than_seats_are_alive_together(self):
        crowd = _crowd()

        assert crowd.outcome, "precondizione: i due figli che occupano i posti non sono arrivati al cancello"
        assert crowd.gate.peak <= 2, (f"con 2 posti e 4 richieste sono stati vivi insieme {crowd.gate.peak} figli "
                                      f"({crowd.gate.created} lanciati in tutto)")

    def test_lookups_waiting_for_a_seat_are_served_when_one_frees(self):
        crowd = _crowd()

        answers = [_answer(run) for run in crowd.runs]

        assert answers == [None] * 4, f"esito delle 4 richieste: {answers}"


_BUSY_WAIT = 0.5          # attesa del posto nei test in cui nessun posto si libera
_BUSY_WAIT_SLACK = 0.4    # quanto oltre l'attesa configurata può durare la richiesta (avvio, rete finta, scheduler)
_QUICK_BUSY_WAIT = 0.3    # attesa del posto quando il rifiuto serve solo come passaggio


@functools.cache
def _without_a_seat():
    """1 posto, tenuto da un figlio fermo; una seconda richiesta, con un'attesa del posto di 0,5 s, resta senza."""

    def scenario(gate, net, start):
        start("acme-typo-first.com")
        held = gate.wait_held(1, patience=10)
        second = start("acme-typo-second.com")
        second.wait(10)
        return SimpleNamespace(held=held, second=second, created=gate.created)

    return _over_a_gate(seats=1, parse_timeout=_BUSY_WAIT, hold=1, scenario=scenario)


class TestLookupWithoutASeat:
    """Chi non ottiene un posto entro `WHOIS_PARSE_TIMEOUT_S` ha un errore di raccolta con un testo fisso, senza
    aver lanciato un figlio: il servizio non accumula lavoro che non può ospitare."""

    def test_it_gets_the_busy_error(self):
        refused = _without_a_seat().outcome

        assert refused.held, "precondizione: il primo figlio non ha occupato il posto"
        assert _answer(refused.second) == _BUSY_ERROR, _answer(refused.second)

    def test_it_has_the_shape_of_a_failed_lookup(self):
        refused = _without_a_seat().outcome
        assert refused.second.body is not None, f"precondizione: {refused.second.describe()}"

        assert _shape(refused.second.body) == _empty_shape("acme-typo-second.com"), refused.second.body

    def test_it_starts_no_child(self):
        refused = _without_a_seat().outcome

        assert refused.created == 1, f"figli lanciati quando la seconda richiesta è stata respinta: {refused.created}"

    def test_it_waits_for_the_configured_time_before_giving_up(self):
        # L'attesa del posto è `WHOIS_PARSE_TIMEOUT_S` (qui `_BUSY_WAIT`): né un rifiuto immediato né un'attesa più
        # lunga, anche solo del doppio: l'attesa si somma alla durata della richiesta.
        refused = _without_a_seat().outcome
        assert refused.second.elapsed is not None, f"precondizione: {refused.second.describe()}"

        assert 0.8 * _BUSY_WAIT <= refused.second.elapsed <= _BUSY_WAIT + _BUSY_WAIT_SLACK, (
            f"attesa del posto: {refused.second.elapsed:.2f} s (configurata {_BUSY_WAIT} s)")


_QUEUE_WAIT = 6.0    # attesa del posto di chi è in coda: il rilascio viene molto prima della scadenza


@functools.cache
def _queued_behind_a_child():
    """1 posto, tenuto da un figlio fermo; una seconda richiesta, con tutto il tempo, aspetta che si liberi.
    Il figlio riparte dopo 0,2 s di attesa della seconda richiesta."""

    def scenario(gate, net, start):
        start("acme-typo-first.com")
        held = gate.wait_held(1, patience=10)
        second = start("acme-typo-second.com")
        finished_early = second.wait(0.2)    # il posto non si libera: una richiesta che finisce qui non ha aspettato
        released = time.perf_counter()
        gate.opened.set()
        second.wait(10)
        return SimpleNamespace(held=held, second=second, finished_early=finished_early, released=released)

    return _over_a_gate(seats=1, parse_timeout=_QUEUE_WAIT, hold=1, scenario=scenario)


class TestLookupWaitingForASeat:
    """Se il posto si libera entro `WHOIS_PARSE_TIMEOUT_S` chi aspettava lo ottiene e il lookup riesce."""

    def test_it_waits_instead_of_giving_up_at_once(self):
        queued = _queued_behind_a_child().outcome

        assert queued.held, "precondizione: il primo figlio non ha occupato il posto"
        assert not queued.finished_early, (f"senza un posto libero la seconda richiesta è finita subito: "
                                           f"{queued.second.describe()}")

    def test_it_gets_the_seat_when_the_child_ends(self):
        queued = _queued_behind_a_child().outcome

        assert queued.second.body is not None, queued.second.describe()
        assert queued.second.body["error"] is None, queued.second.body["error"]
        assert queued.second.body["registrar"] == "Registrar Example Inc.", queued.second.body

    def test_it_gets_the_seat_right_after_the_release_and_not_at_the_end_of_the_wait(self):
        # Chi aspetta viene svegliato dal rilascio. Se si accorgesse del posto libero solo alla scadenza
        # dell'attesa (qui 6 s) il lookup durerebbe quanto l'attesa, con il posto libero per quasi tutto il tempo.
        # Il limite è metà dell'attesa: a riposo il lookup finisce ~0,3 s dopo il rilascio, con 8 processi su 4 core
        # ~1,2 s, e senza risveglio ~5,8 s.
        queued = _queued_behind_a_child().outcome
        assert queued.second.elapsed is not None, f"precondizione: {queued.second.describe()}"

        latency = queued.second.started + queued.second.elapsed - queued.released

        assert latency <= _QUEUE_WAIT / 2, (f"la seconda richiesta è finita {latency:.2f} s dopo il rilascio del "
                                            f"posto (attesa configurata {_QUEUE_WAIT} s)")


# ── Il rifiuto per mancanza di posto non si ricorda ────────────────────────

_RETRIED_DOMAIN = "acme-typo-retried.com"


@functools.cache
def _refused_then_retried():
    """1 posto, tenuto da un figlio fermo: la prima richiesta per `_RETRIED_DOMAIN` resta senza posto. Il figlio
    riparte e libera il posto; la stessa richiesta si ripete SENZA svuotare la cache del servizio."""

    def scenario(gate, net, start):
        first = start("acme-typo-first.com")
        held = gate.wait_held(1, patience=10)
        refused = start(_RETRIED_DOMAIN)
        refused.wait(10)
        before = net.connections_to(REGISTRY)
        gate.opened.set()
        first.wait(20)
        # Il parsing del secondo tentativo ha tempo: il tetto breve serviva solo a far scadere l'attesa del posto.
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", _SEAT_PATIENCE, raising=False)
            retried = start(_RETRIED_DOMAIN)
            retried.wait(20)
        return SimpleNamespace(held=held, refused=refused, retried=retried, before=before,
                               after=net.connections_to(REGISTRY))

    return _over_a_gate(seats=1, parse_timeout=_QUICK_BUSY_WAIT, hold=1, scenario=scenario)


class TestRefusalForLackOfASeatIsNotRemembered:
    """Restare senza posto dipende dal carico di quel momento, non dal dominio: se entrasse nella cache del
    servizio (dove restano le raccolte fallite e le osservazioni) il dominio respinto avrebbe lo stesso errore
    per tutta la durata della cache anche a posti liberi."""

    def test_a_retry_with_a_free_seat_queries_the_network_again(self):
        retry = _refused_then_retried().outcome
        assert retry.held and _answer(retry.refused) == _BUSY_ERROR, (
            f"precondizione: la prima richiesta doveva restare senza posto: {_answer(retry.refused)!r}")

        assert retry.after > retry.before, (
            f"la seconda richiesta per lo stesso dominio non ha interrogato la rete (servita dalla cache): "
            f"{retry.before} connessioni al registro prima, {retry.after} dopo")

    def test_a_retry_with_a_free_seat_gets_the_observation(self):
        retry = _refused_then_retried().outcome
        assert retry.held and _answer(retry.refused) == _BUSY_ERROR, (
            f"precondizione: la prima richiesta doveva restare senza posto: {_answer(retry.refused)!r}")

        body = retry.retried.body

        assert body is not None, retry.retried.describe()
        assert body["error"] is None and body["registrar"] == "Registrar Example Inc.", body["error"]


class TestWallTimeoutOfTheChildStaysInTheCache:
    """Il confine opposto: la scadenza di parete del figlio è anche l'esito di una risposta ostile del registro e
    resta in cache come ogni raccolta fallita (la richiesta successiva non interroga la rete)."""

    def test_the_second_request_does_not_query_the_network_and_gets_the_same_error(
            self, lookup, whois_network, monkeypatch):
        # `lookup` svuota la cache a ogni chiamata: qui serve il client, senza svuotarla.
        api = TestClient(whois_service.app)
        whois_network.registry("com", _com_registry(None))
        monkeypatch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", 0.001, raising=False)

        first = api.get("/whois", params={"domain": COM}).json()
        queried = len(whois_network.contacted)
        second = api.get("/whois", params={"domain": COM}).json()

        assert first["error"] == _FAILED_ERROR, f"precondizione: {first['error']!r}"
        assert queried > 0, "precondizione: la prima richiesta interroga la rete"
        assert len(whois_network.contacted) == queried, (
            f"la seconda richiesta ha interrogato la rete: {whois_network.contacted[queried:]}")
        assert second["error"] == first["error"], (first["error"], second["error"])


# ── Il posto si libera a ogni esito ────────────────────────────────────────

def _popen_that_cannot_start(*_, **__):
    raise OSError(24, "Too many open files")


def _popen_that_explodes(*_, **__):
    raise RuntimeError("popen exploded")


class _CommunicateExplodes(_REAL_POPEN):
    def communicate(self, input=None, timeout=None):
        raise RuntimeError("communicate exploded")


# Ogni modo in cui un lookup può uscire dal figlio, e come lo si provoca.
_OUTCOMES = ["success", "parser-error", "start-failure", "wall-timeout", "popen-raises", "communicate-raises"]


def _provoke(outcome, patch):
    if outcome == "start-failure":
        patch.setattr(whois_service.subprocess, "Popen", _popen_that_cannot_start)
    elif outcome == "wall-timeout":
        patch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", 0.001, raising=False)
    elif outcome == "popen-raises":
        patch.setattr(whois_service.subprocess, "Popen", _popen_that_explodes)
    elif outcome == "communicate-raises":
        patch.setattr(whois_service.subprocess, "Popen", _CommunicateExplodes)


class TestTheSeatIsFreedOnEveryOutcome:
    """Con un solo posto, dopo un lookup finito in qualunque modo il successivo ottiene il posto e riesce: un
    posto non liberato resterebbe occupato fino al riavvio e ogni lookup seguente scadrebbe senza posto."""

    @pytest.mark.parametrize("outcome", _OUTCOMES)
    def test_the_next_lookup_gets_the_seat(self, lookup, whois_network, monkeypatch, outcome):
        monkeypatch.setattr(whois_service, "WHOIS_PARSE_MAX_CHILDREN", 1, raising=False)
        monkeypatch.setattr(whois_service, "WHOIS_PARSE_TIMEOUT_S", 5, raising=False)
        whois_network.registry("com", _NOT_REGISTERED_COM if outcome == "parser-error" else _com_registry(None))
        with monkeypatch.context() as patch:
            _provoke(outcome, patch)
            first = lookup(COM)
        assert (first["error"] is None) == (outcome == "success"), f"precondizione, primo lookup: {first['error']!r}"
        whois_network.registry("com", _com_registry(None))

        second = lookup(COM)

        assert second["error"] is None and second["registrar"] == "Registrar Example Inc.", (
            f"dopo un lookup finito con «{outcome}» il successivo non ha avuto il posto: {second['error']!r}")


# ── La causa di un guasto di rete resta nel log ────────────────────────────

class TestNetworkFailureIsLogged:
    """Il servizio registra l'esito di un lookup fallito (con il dominio sanificato), non la causa: la causa di
    un guasto di rete è l'eccezione del socket, e la riga che la porta è quella della libreria."""

    def test_the_library_logs_why_the_registry_refused_the_connection(self, lookup, whois_network, caplog):
        whois_network.registry("com", whois_network.REFUSED)

        with caplog.at_level(logging.ERROR, logger="whois.whois"):
            lookup(COM)

        logged = [record.getMessage() for record in caplog.records if record.name == "whois.whois"]
        assert any(whois_network.REFUSED.text in message for message in logged), (
            f"righe di log della libreria (cercato «{whois_network.REFUSED.text}»): {logged}")
