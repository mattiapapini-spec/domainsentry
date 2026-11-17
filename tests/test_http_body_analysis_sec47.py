"""Tests per l'analisi del corpo delle pagine in `/http` — una pagina ostile non deve fermare il processo (SEC-47).

`/http` (services/http_fingerprint.py) scarica fino a quattro pagine di un dominio (http/https, con e senza `www.`)
e ne analizza il corpo con `normalize_html_for_fingerprint`, `extract_visible_text`, `detect_suspicious_patterns`,
`detect_hidden_elements` (shared/utils.py) e con l'estrazione del titolo. Il corpo lo sceglie chi controlla il
dominio sosia, e la pipeline lo visita da sé: non serve altro per innescare l'analisi. Se una regex rilegge il corpo
fino alla fine da ogni ripetizione di un'apertura senza chiusura (`<script>`, `<!--`, `<title>`, `<` senza `>`, un
tag d'apertura con un attributo cercato più avanti, `data:` senza `;base64,`), il costo cresce col quadrato o col
cubo della dimensione; e poiché `re` tiene il GIL per tutta la chiamata, nel frattempo dashboard, sonde di salute e
login dello stesso processo restano fermi.

Comportamento richiesto:

- Il costo di ciascuna funzione cresce in modo lineare con il corpo, su ogni famiglia di corpo ostile.
- Un altro thread del processo non resta fermo mentre si analizza un corpo ostile.
- Il gestore di `/http` analizza un corpo alla volta in tutto il processo, anche fra richieste concorrenti e dopo
  un'attesa lunga quanto si vuole: quattro analisi lunghe insieme si contenderebbero il GIL una chiamata dopo l'altra
  (SEC-48: nessuna fuga dal turno). Fra i corpi in attesa entra prima il più corto, a parità di lunghezza il primo
  arrivato: finché nessun corpo in coda è invecchiato, una pagina normale passa avanti alle pagine ostili. Un corpo che
  ha atteso più di `ANALYSIS_AGING_S` (costante del modulo del servizio, 10 s, letta a ogni passaggio del turno
  sull'orologio `_turn_clock`) entra prima di ogni corpo arrivato dopo di lui: nessuno aspetta più di quel tempo più le
  analisi dei corpi che aveva davanti. Sotto un carico sostenuto la coda invecchia e va in ordine d'arrivo, e una pagina
  normale aspetta tutte le analisi in coda davanti a lei. I corpi della stessa `/http` aspettano il turno insieme ed
  entrano uno alla volta. Il turno non si perde: né se l'analisi solleva, né se solleva l'attesa; e non ha mai due
  titolari. Valvola di sicurezza: un turno tenuto più di `ANALYSIS_STUCK_S` (60 s, letta a ogni controllo sull'orologio
  del turno) è perso per un difetto, perché un'analisi dura pochi secondi: passa a chi l'ordine normale designa fra i
  corpi delle altre richieste, uno solo, con un errore nel log senza dati della pagina; se aspettano solo corpi della
  richiesta del corpo bloccato, la valvola non passa nulla e non registra nulla. Chi teneva il turno, se finisce, non lo
  ripassa; un turno consegnato mentre l'attesa scade non è preso per bloccato. Finché un corpo di una richiesta è in
  analisi, anche dopo la valvola, nessun altro corpo di quella richiesta riceve il turno, né dalla valvola né da un
  passaggio né trovandolo libero; quando quel corpo finisce, un turno libero va subito al prossimo designato.
- Le liste di `detect_hidden_elements` tengono al più 100 elementi, nell'ordine del documento; una lista che ne
  ha 100 o meno resta intera. Rischio, `summary` e conteggi sono quelli della pagina intera, il totale di una
  lista tagliata si legge dal risultato, e gli alert del classificatore e il conteggio dei pixel nella dashboard
  non cambiano quando l'elemento che li decide sta oltre la posizione 100. Il div che decide l'alert prende un
  posto della lista, non uno in più. La dashboard dice quanti pixel non elenca.
- Le scelte delle regex sostituite restano: l'ultimo `content=` di un meta refresh, l'ultimo attributo di un div
  che lo nasconde, l'ultimo token di un form o di un input, `data:` con un tipo prima di `;base64,`.
- La risposta di `/http` di una pagina che moltiplica gli elementi nascosti resta sotto mezzo MiB, e la richiesta
  a `/classify/variant` che l'orchestratore ne costruisce resta sotto 1 MiB.
- Sulle pagine leggibili impronta, testo visibile, titolo, pattern sospetti ed elementi nascosti sono quelli
  dell'analisi senza tetto, fissati qui.

Come si misura. Il costo è il tempo di CPU del thread che chiama la funzione (`time.thread_time`; per il gestore,
che usa più thread, `time.process_time`), misurato in un interprete separato: una regex non si interrompe dal suo
stesso processo, e sul codice super-lineare una sola misura dura minuti; scaduto il tempo, l'interprete si uccide.
Si confronta il costo a 64 KiB e a 256 KiB: un costo lineare cresce di circa 4 volte, uno quadratico di 16. Il
tempo di CPU risente poco degli altri processi, ma su una macchina condivisa a tratti si gonfia: un rapporto oltre
la soglia si rimisura per qualche secondo, con le due dimensioni alternate, e conta il minimo per dimensione. Il
fermo di un altro thread si misura con un thread di battito nello stesso processo dei test, su corpi di pochi KiB
che il codice super-lineare impiega già secondi ad analizzare. Nessun corpo da 2 MiB: la suite ha poco margine di
tempo, e la linearità fra 64 e 256 KiB e il tetto alle liste dicono già cosa succede a 2 MiB.

Isolamento di rete: **nessuna connessione**. Il gestore vero gira dietro `TestClient`, con lo scaricamento
(`http_get_with_retry` nel modulo del servizio) sostituito da un sito finto che serve pagine scritte qui. Domini
`.example`.
"""
import functools
import hashlib
import json
import logging
import os
import queue
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import services.classifier as classifier
import services.http_fingerprint as http_fingerprint
import shared.utils as utils
from services.classifier import DiffInput, baseline_diff
from shared.constants import DEFAULT_SUSPICIOUS_PATTERNS
from shared.security import MAX_BODY_SIZE
from shared.utils import detect_hidden_elements, detect_suspicious_patterns

_ROOT = Path(__file__).resolve().parent.parent
_KIB = 1024

_SITE = "sito.example"                # il dominio servito dal sito finto
_LEGIT = "sito-cliente.example"       # il dominio legittimo di un cliente, per gli alert del classificatore
_LOOKALIKE = "sito-cllente.example"   # un sosia


# ── Corpi ostili ──────────────────────────────────────────────────────────────────────────────

# Le famiglie individuate nell'indagine: (inizio, unità ripetuta, fine). Ognuna fa rileggere a una regex con
# `.*?` o `[^>]*` non ancorato il corpo fino alla fine, da ogni ripetizione dell'unità.
_FAMILIES = {
    "script": ("", "<script>", ""),                      # apertura senza `</script>`
    "style": ("", "<style>", ""),
    "comment": ("", "<!--", ""),                         # commento mai chiuso
    "title": ("", "<title>", ""),
    "title_open": ("", "<title ", ""),                   # tag del titolo senza `>`
    "lt": ("", "<", ""),                                 # `<` senza `>`
    "form": ("", "<form ", ""),                          # `<form` senza `action` né `>`
    "input": ("", "<input ", ""),                        # `<input` senza `type=password|email` né `>`
    "input_hidden": ("", "<input type=hidden ", ""),     # il tipo c'è, la `>` no
    "meta": ("", "<meta http-equiv=refresh ", ""),       # `http-equiv` c'è, `content` e `>` no
    "div_display": ("", '<div style="display:none', ""),  # stile nascosto senza apice di chiusura
    "div": ("", "<div ", ""),
    "div_class": ("", '<div class="', ""),
    "data": ("", "data:", ""),                           # `data:` senza `;base64,`
    "div_lt": ('<div style="display:none">', "< testo visibile ", "</div>"),  # div nascosto con `<` senza `>`
}

# Aperture che condividono un solo `>` in fondo al corpo: una scansione che da ogni apertura ricercasse quel `>`,
# o ripartisse dall'apertura invece che da lì, rileggerebbe il corpo ogni volta. Gli spazi diradano gli attributi
# del tag; il testo CJK nei valori di `style` rende costosa ogni rilettura del tag fino al `>`.
_CLOSED_FAMILIES = {
    "div_gt": ("", "<div" + " " * 48, ">"),
    "div_style_gt": ("<div", " style='display:none \u3e3e\u3e3e'", ">"),
    "input_gt": ("", "<input" + " " * 48, ">"),
    "form_gt": ("", "<form" + " " * 48, ">"),
    "meta_gt": ("", "<meta http-equiv=refresh" + " " * 48, ">"),
}
_ALL_FAMILIES = {**_FAMILIES, **_CLOSED_FAMILIES}


def _hostile(family, size):
    head, unit, tail = _ALL_FAMILIES[family]
    n = size - len(head) - len(tail)
    return head + (unit * (n // len(unit) + 1))[:n] + tail


# ── Sito finto e servizio ─────────────────────────────────────────────────────────────────────

# Il thread che scarica una pagina è quello che poi la analizza: lì `_FakeSite.fetch` lascia il marcatore della
# pagina, e `_TurnWaits` riconosce l'attesa del turno di quel corpo.
_TURN_THREAD = threading.local()


def _marker_of(html):
    found = re.search(r"corpo-\w+", html or "")
    return found.group() if found else None


class _FakeSite:
    """Al posto dello scaricamento: risponde 200 con la pagina assegnata all'URL, altrimenti come una
    connessione rifiutata (nessuna pagina analizzata)."""

    def __init__(self):
        self.pages = {}
        self.fetched = {}      # URL servito -> evento, segnalato quando /http lo scarica

    def serve(self, domain, html, everywhere=False):
        """Assegna `html` a `http://dominio` (e, con `everywhere`, anche agli altri tre URL di `/http`)."""
        urls = [f"http://{domain}"]
        if everywhere:
            urls += [f"https://{domain}", f"http://www.{domain}", f"https://www.{domain}"]
        for url in urls:
            self.pages[url] = html
            self.fetched[url] = threading.Event()

    def fetch(self, url, timeout=15, **kwargs):
        if url in self.fetched:
            self.fetched[url].set()
        html = self.pages.get(url)
        _TURN_THREAD.marker = _marker_of(html)
        if html is None:
            return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                    "error": "connection refused", "attempts": 1}
        return {"status_code": 200, "content": html.encode("utf-8"), "headers": {"Server": "nginx"},
                "final_url": url, "error": None, "attempts": 1}


@pytest.fixture
def site(monkeypatch):
    fake = _FakeSite()
    monkeypatch.setattr(http_fingerprint, "http_get_with_retry", fake.fetch)
    return fake


@pytest.fixture(scope="module")
def http_client():
    with TestClient(http_fingerprint.app) as client:
        yield client


def _http(client, domain=_SITE, check_www=True):
    response = client.get("/http", params={"domain": domain, "check_www": check_www})
    assert response.status_code == 200, f"/http ha risposto {response.status_code}: {response.text[:300]}"
    return response


def _active_checks(response):
    return [c for c in response.json()["checks"] if c["status_code"] == 200]


# ── Costo lineare ─────────────────────────────────────────────────────────────────────────────

_COST_SIZES = (64 * _KIB, 256 * _KIB)
# Lineare: ~4 (misurato 3,1-5,5 su una riscrittura lineare). Quadratico: ~16, e a queste dimensioni il codice
# super-lineare di solito non arriva nemmeno alla seconda misura entro il tempo concesso.
_LINEAR_RATIO_LIMIT = 8.0
# Su una macchina condivisa il tempo di CPU di un thread a tratti si gonfia (fino a 2-3 volte), e un tratto può
# durare qualche decimo di secondo, cioè più tentativi di fila: misurando la piccola e poi la grande, una sola
# piccola presa prima del tratto e tutte le grandi prese dentro bastano a portare un costo lineare oltre la
# soglia. Un rapporto oltre la soglia si rimisura quindi per `_COST_RETRY_S` secondi, più a lungo di quei tratti,
# con `_COST_RETRY_PAIRS` coppie per tentativo e le due dimensioni alternate (piccola, grande, piccola, grande...),
# così un tratto gonfia entrambe; conta il minimo per dimensione, che stima il costo senza disturbi. Il codice
# quadratico, il cui costo vero cresce di 16 volte, resta oltre la soglia a ogni misura.
_COST_RETRY_PAIRS = 3
_COST_RETRY_S = 3.0
# Secondi di parete per una coppia (funzione, famiglia): riscaldamento a 4 KiB, una misura a 64 e una a 256 KiB.
# Un'analisi lineare ci mette decine di millisecondi; sul codice quadratico la misura a 64 KiB dura già secondi.
_COST_BUDGET_S = 2.5
_WORKER_START_TIMEOUT_S = 60

# Eseguito da un interprete separato (`python -c`), che importa il codice dalla radice del repository.
_WORKER_SOURCE = r'''
import gc, json, sys, time

sys.path.insert(0, sys.argv[1])
from shared import utils
from shared.constants import DEFAULT_SUSPICIOUS_PATTERNS


def _http_analysis():
    # L'analisi del gestore vero di /http senza elementi nascosti: è dove sta l'estrazione del titolo.
    from fastapi.testclient import TestClient
    import services.http_fingerprint as service
    page = {}

    def fetch(url, timeout=15, **kwargs):
        if url == "http://corpo.example":
            return {"status_code": 200, "content": page["body"], "headers": {}, "final_url": url,
                    "error": None, "attempts": 1}
        return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                "error": "connection refused", "attempts": 1}

    service.http_get_with_retry = fetch
    client = TestClient(service.app)

    def analyse(html):
        page["body"] = html.encode("utf-8")
        response = client.get("/http", params={"domain": "corpo.example", "check_www": "false",
                                               "detect_hidden": "false"})
        if response.status_code != 200:
            raise RuntimeError("/http ha risposto %d" % response.status_code)
    return analyse, time.process_time


FUNCTIONS = {
    "normalize": lambda: (utils.normalize_html_for_fingerprint, time.thread_time),
    "visible": lambda: (utils.extract_visible_text, time.thread_time),
    "suspicious": lambda: (lambda html: utils.detect_suspicious_patterns(html, DEFAULT_SUSPICIOUS_PATTERNS),
                           time.thread_time),
    "hidden": lambda: (lambda html: utils.detect_hidden_elements(html, self_domain="corpo.example"),
                       time.thread_time),
    "http": _http_analysis,
}


def body(head, unit, tail, size):
    n = size - len(head) - len(tail)
    return head + (unit * (n // len(unit) + 1))[:n] + tail


def reply(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()


gc.disable()
prepared = {}
reply(ready=True)
for line in sys.stdin:
    request = json.loads(line)
    if "prepare" in request:
        prepared[request["prepare"]] = FUNCTIONS[request["prepare"]]()
        reply(ready=True)
        continue
    function, clock = prepared[request["function"]]
    head, unit, tail = request["body"]
    function(body(head, unit, tail, 4096))
    for size, repeat in request["sizes"]:
        html = body(head, unit, tail, size)
        best = None
        for _ in range(repeat):
            started = clock()
            function(html)
            spent = clock() - started
            best = spent if best is None else min(best, spent)
        reply(size=size, cpu=best)
'''

_TIMED_OUT = object()


class _CostWorker:
    """L'interprete separato che misura i costi. Uno solo per modulo; se una misura sfora il tempo concesso viene
    ucciso, e la misura successiva ne avvia un altro."""

    def __init__(self, log_path):
        self._log_path = log_path
        self._proc = None

    def _start(self):
        self._log = open(self._log_path, "ab")
        self._proc = subprocess.Popen([sys.executable, "-c", _WORKER_SOURCE, str(_ROOT)], cwd=str(_ROOT),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._log,
                                      text=True, bufsize=1)
        self._lines = queue.Queue()
        self._reader = threading.Thread(target=self._pump, args=(self._proc.stdout, self._lines), daemon=True)
        self._reader.start()
        self._prepared = set()
        self._expect_ready()

    @staticmethod
    def _pump(stream, lines):
        for line in stream:
            lines.put(line)
        lines.put(None)

    def _log_tail(self):
        try:
            return Path(self._log_path).read_text(errors="replace")[-1500:]
        except OSError:
            return ""

    def _next(self, timeout):
        try:
            line = self._lines.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return _TIMED_OUT
        if line is None:
            self.stop()
            pytest.fail(f"l'interprete di misura è terminato: {self._log_tail()}", pytrace=False)
        return json.loads(line)

    def _expect_ready(self):
        if self._next(_WORKER_START_TIMEOUT_S) is _TIMED_OUT:
            self.stop()
            pytest.fail(f"l'interprete di misura non è partito entro {_WORKER_START_TIMEOUT_S} s", pytrace=False)

    def _send(self, **request):
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()

    def measure(self, function, family, pairs=1, budget=_COST_BUDGET_S):
        """{dimensione: secondi di CPU, il minimo di `pairs` misure} e la prima dimensione non finita entro `budget`
        secondi (None se tutte). Le dimensioni si alternano, una misura alla volta, con il garbage collector spento."""
        if self._proc is None or self._proc.poll() is not None:
            self._start()
        if function not in self._prepared:
            self._send(prepare=function)
            self._expect_ready()
            self._prepared.add(function)
        small, large = _COST_SIZES
        self._send(function=function, body=_ALL_FAMILIES[family], sizes=[[small, 1], [large, 1]] * pairs)
        deadline = time.monotonic() + budget
        cpu = {}
        for size in _COST_SIZES * pairs:
            message = self._next(deadline - time.monotonic())
            if message is _TIMED_OUT:
                self.stop()
                return cpu, size
            cpu[message["size"]] = min(message["cpu"], cpu.get(message["size"], message["cpu"]))
        return cpu, None

    def stop(self):
        if self._proc is not None:
            self._proc.kill()
            self._proc.wait()
            # Lo stdout si chiude solo dopo che il lettore ha visto la fine del flusso, mai sotto di lui.
            self._reader.join(10)
            for stream in (self._proc.stdin, self._proc.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
            self._log.close()
            self._proc = None


@pytest.fixture(scope="module")
def cost_worker(tmp_path_factory):
    worker = _CostWorker(tmp_path_factory.mktemp("sec47") / "worker.log")
    yield worker
    worker.stop()


def _assert_linear(cost_worker, function, family, label):
    small, large = _COST_SIZES
    cpu = {}
    pairs, until = 1, time.monotonic() + _COST_RETRY_S
    while True:
        measured, unfinished = cost_worker.measure(function, family, pairs)
        cpu = {size: min(seconds, cpu.get(size, seconds)) for size, seconds in measured.items()}
        if unfinished is not None or cpu[large] / max(cpu[small], 1e-6) < _LINEAR_RATIO_LIMIT:
            break
        if time.monotonic() >= until:
            break
        pairs = _COST_RETRY_PAIRS
    done = ", ".join(f"{size // _KIB} KiB {seconds * 1000:.1f} ms" for size, seconds in cpu.items())
    assert unfinished is None, (
        f"{label} su un corpo «{family}» non finisce entro {_COST_BUDGET_S} s a {unfinished // _KIB} KiB "
        f"(misure finite: {done or 'nessuna'}); un costo lineare a questa dimensione è di decine di millisecondi")
    ratio = cpu[large] / max(cpu[small], 1e-6)
    assert ratio < _LINEAR_RATIO_LIMIT, (
        f"{label} su un corpo «{family}»: {done}, rapporto {ratio:.1f} per un corpo 4 volte più grande "
        f"(lineare ~4, quadratico ~16; soglia {_LINEAR_RATIO_LIMIT})")


_FUNCTION_LABELS = {
    "normalize": "normalize_html_for_fingerprint",
    "visible": "extract_visible_text",
    "suspicious": "detect_suspicious_patterns",
    "hidden": "detect_hidden_elements",
}


def _cost_cases():
    for function in _FUNCTION_LABELS:
        for family in _FAMILIES:
            if function == "hidden" and family == "lt":
                # Le regex di detect_hidden_elements non trovano lavoro su `<` ripetuto: il `<` senza `>` che ne
                # raggiunge una, dentro un div nascosto, è la famiglia `div_lt`.
                continue
            yield pytest.param(function, family, id=f"{function}-{family}")
    # Le famiglie col `>` in fondo, con la funzione che ha la scansione da esercitare: div, input nascosti e meta
    # refresh in detect_hidden_elements; i pattern `<form[^>]*action` e `<input[^>]*type=...` nei sospetti.
    for function, family in (("hidden", "div_gt"), ("hidden", "div_style_gt"), ("hidden", "input_gt"),
                             ("hidden", "meta_gt"), ("suspicious", "input_gt"), ("suspicious", "form_gt")):
        yield pytest.param(function, family, id=f"{function}-{family}")


class TestCostIsLinear:
    """Il costo di ciascuna funzione di analisi cresce in modo lineare con il corpo, su ogni famiglia ostile."""

    @pytest.mark.parametrize("function, family", list(_cost_cases()))
    def test_cost_grows_linearly_with_the_body(self, cost_worker, function, family):
        _assert_linear(cost_worker, function, family, _FUNCTION_LABELS[function])

    @pytest.mark.parametrize("family", ["title", "title_open"])
    def test_the_analysis_of_http_grows_linearly_with_the_body(self, cost_worker, family):
        """Il gestore aggiunge alle quattro funzioni l'estrazione del titolo: l'apertura `<title` ripetuta senza
        chiusura è l'unico corpo che la rende super-lineare."""
        _assert_linear(cost_worker, "http", family, "l'analisi di /http (senza elementi nascosti)")


# ── Nessun fermo di un altro thread ───────────────────────────────────────────────────────────

# Pochi KiB, dove il codice super-lineare impiega già oltre un secondo per corpo e un'analisi lineare pochi ms.
_STALL_CASES = [("meta", 8 * _KIB), ("input_hidden", 12 * _KIB), ("div_display", 12 * _KIB), ("script", 32 * _KIB)]
# Il battito si risveglia ogni 5 ms; il resto è il tempo di uno scheduler carico.
_STALL_LIMIT_S = 0.25


class _Heartbeat:
    """Un thread che dorme 5 ms in ciclo: l'intervallo massimo fra due risvegli dice per quanto un altro thread
    del processo ha tenuto il GIL."""

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
        time.sleep(0.01)
        self.gaps.clear()
        return self

    def __exit__(self, *exc):
        self.stopped = True
        self.thread.join()

    @property
    def longest_stall(self):
        return max(self.gaps) if self.gaps else 0.0


class TestNoOtherThreadIsStalled:
    @pytest.mark.parametrize("family, size", _STALL_CASES, ids=[f"{f}-{s // _KIB}KiB" for f, s in _STALL_CASES])
    def test_another_thread_keeps_running_while_a_hostile_page_is_analysed(self, site, http_client, family, size):
        site.serve(_SITE, _hostile(family, size))
        started = time.perf_counter()
        with _Heartbeat() as beat:
            response = _http(http_client, check_www=False)
        elapsed = time.perf_counter() - started

        assert len(_active_checks(response)) == 1, "la pagina non è stata analizzata"
        assert beat.longest_stall < _STALL_LIMIT_S, (
            f"un altro thread è rimasto fermo {beat.longest_stall:.2f} s mentre /http analizzava {size // _KIB} KiB "
            f"«{family}» (richiesta di {elapsed:.2f} s; soglia {_STALL_LIMIT_S} s)")


# ── Un'analisi di corpo alla volta ────────────────────────────────────────────────────────────

_ANALYSIS_FUNCTIONS = ("normalize_html_for_fingerprint", "extract_visible_text", "detect_suspicious_patterns",
                       "detect_hidden_elements")


def _readable_page(marker):
    return (f"<html><head><title>Pagina {marker}</title><style>p{{color:#333}}</style></head><body>"
            f"<h1>Benvenuto</h1><p>Testo della pagina {marker} con un modulo di accesso.</p>"
            f'<form action="/login" method="post"><input name="utente"><input type="password" name="pwd">'
            f'<input type="hidden" name="tok" value="{marker}"></form><script>var t=1;</script></body></html>')


class TestOneBodyIsAnalysedAtATime:
    def test_concurrent_requests_never_analyse_two_bodies_at_once(self, site, http_client, monkeypatch):
        """Due `/http` concorrenti, otto pagine diverse: le chiamate delle quattro funzioni di analisi di una pagina
        non si intrecciano con quelle di un'altra. Le funzioni sono avvolte dove il gestore e il modulo comune le
        trovano, e ogni chiamata attende 5 ms prima di analizzare, così due analisi parallele si sovrappongono
        di sicuro. Il marcatore nella pagina dice di quale corpo si tratta. L'attesa massima del turno è alzata a
        30 s: la proprietà vale finché l'attesa non scade."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, 30.0, raising=False)
        markers = [f"corpo-{n}" for n in range(8)]
        domains = ["primo.example", "secondo.example"]
        urls = [f"{scheme}://{host}" for domain in domains
                for host in (domain, f"www.{domain}") for scheme in ("http", "https")]
        for url, marker in zip(urls, markers, strict=True):
            site.pages[url] = _readable_page(marker)

        calls, record = [], threading.Lock()

        def wrap(function):
            def analysis(html, *args, **kwargs):
                started = time.perf_counter()
                time.sleep(0.005)
                try:
                    return function(html, *args, **kwargs)
                finally:
                    marker = next((m for m in markers if m in html), None)
                    with record:
                        calls.append((marker, started, time.perf_counter()))
            return analysis

        for name in _ANALYSIS_FUNCTIONS:
            for module in (http_fingerprint, utils):
                if hasattr(module, name):
                    monkeypatch.setattr(module, name, wrap(getattr(module, name)))

        responses = {}
        threads = [threading.Thread(target=lambda d=d: responses.__setitem__(d, _http(http_client, d)))
                   for d in domains]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)

        assert set(responses) == set(domains), "una delle due richieste non è finita"
        spans = {}
        for marker, start, end in calls:
            first, last = spans.get(marker, (start, end))
            spans[marker] = (min(first, start), max(last, end))
        assert set(spans) >= set(markers), (
            f"il gestore non ha chiamato le funzioni di analisi per tutte le pagine: viste {sorted(spans)}")
        ordered = sorted((span, marker) for marker, span in spans.items() if marker is not None)
        overlaps = [(a, b) for (span_a, a), (span_b, b) in zip(ordered, ordered[1:], strict=False)
                    if span_b[0] < span_a[1]]
        assert not overlaps, f"analisi di corpi diversi sovrapposte: {overlaps}"


# ── Il turno dell'analisi: uno alla volta, il più corto per primo, con invecchiamento ─────────

# Nome di un'attesa massima del turno, scaduta la quale un corpo sarebbe analizzato accanto agli altri (una fuga dal
# turno). Il turno non ha un'attesa massima: i test che escludono una fuga impostano comunque questa costante a un
# centesimo di secondo (`raising=False`), così un servizio che ne tenesse conto lascerebbe entrare la pagina in coda
# accanto all'analisi in corso, e il test lo vedrebbe. Gli altri test che la alzano non cambiano nulla.
_MAX_WAIT = "ANALYSIS_MAX_WAIT_S"
# Invecchiamento della coda: un corpo che ha atteso più di `ANALYSIS_AGING_S` secondi, sull'orologio `_turn_clock`
# del servizio, entra prima di ogni corpo arrivato dopo di lui. I test sostituiscono l'orologio con `_TurnClock`
# (`raising=False`, come sopra): l'età di un corpo in coda cambia solo quando il test lo fa avanzare.
_AGING = "ANALYSIS_AGING_S"
_CLOCK = "_turn_clock"
# Valvola di sicurezza: un turno tenuto più di `ANALYSIS_STUCK_S` secondi, sullo stesso orologio, passa al prossimo in
# coda. I corpi in coda lo controllano ogni `ANALYSIS_STUCK_POLL_S` secondi veri: i test che la provano mettono il
# controllo a un centesimo di secondo, e aspettano che la pagina entri al più `_VALVE_S`.
_STUCK = "ANALYSIS_STUCK_S"
_POLL = "ANALYSIS_STUCK_POLL_S"
_VALVE_S = 10
# Una consegna che arriva mentre l'attesa di controllo scade si provoca fermando quell'attesa dopo la scadenza: serve
# che il corpo in coda aspetti il turno con un `threading.Event.wait` a tempo (`_TurnWaits`).
_NOT_PAUSED = ("l'attesa di controllo della pagina non è scaduta in un `threading.Event.wait` a tempo, dove il test la "
               "ferma dopo la scadenza")
# Una pagina che una fuga dal turno lasciasse entrare accanto all'analisi in corso ci entrerebbe in pochi ms; il
# turno stretto non la fa entrare mai, quindi l'esito non dipende da questo tempo.
_ALONGSIDE_S = 1.0
# Oltre l'attesa: l'analisi di una pagina leggibile, `TestClient` e uno scheduler carico.
_WAIT_MARGIN_S = 1.5
_HOLD_LIMIT_S = 20     # un'analisi trattenuta si sblocca da sé dopo questo tempo, se il test non l'ha già fatto
# Entro quanto una pagina senza contesa entra nell'analisi. I test che lo usano alzano l'attesa massima a
# `_LONG_WAIT_S`: una pagina che trova il turno occupato resta ferma ben oltre, e l'esito non dipende dai tempi.
_ENTRY_S = 5
_LONG_WAIT_S = 15


def _quiet_wait(event, timeout):
    """`event.wait` che `_TurnWaits` non osserva: le attese dei test non sono attese del turno."""
    _QUIET.active = True
    try:
        return event.wait(timeout)
    finally:
        _QUIET.active = False


class _Quiet(threading.local):
    active = False


_QUIET = _Quiet()


class _AnalysisGate:
    """Avvolge le quattro funzioni di analisi dove il gestore e il modulo comune le trovano. Registra l'ordine in
    cui i corpi entrano nell'analisi (dal marcatore `corpo-…` della pagina), gli intervalli delle chiamate e quanti
    corpi diversi sono dentro una chiamata nello stesso momento. Trattiene, finché `release()`, l'analisi dei corpi
    in `held` (un'analisi lunga in corso) e fa sollevare quella dei corpi in `failing`."""

    def __init__(self, monkeypatch, held=(), failing=(), pause_s=0.0):
        self.held = {held} if isinstance(held, str) else set(held)
        self.failing, self.pause_s = set(failing), pause_s
        self.order, self.spans, self.most_together = [], [], 0
        self._inside, self._entered, self._released = {}, {}, {}
        self._record = threading.Lock()
        for name in _ANALYSIS_FUNCTIONS:
            for module in (http_fingerprint, utils):
                if hasattr(module, name):
                    monkeypatch.setattr(module, name, self._wrap(getattr(module, name)))

    def _event(self, table, marker):
        with self._record:
            return table.setdefault(marker, threading.Event())

    def entered(self, marker):
        """Evento: il corpo `marker` è entrato nell'analisi."""
        return self._event(self._entered, marker)

    @property
    def holding(self):
        return self.entered(sorted(self.held)[0])

    def release(self, marker=None):
        for held in [marker] if marker else self.held:
            self._event(self._released, held).set()

    def _wrap(self, function):
        def analysis(html, *args, **kwargs):
            marker = _marker_of(html)
            with self._record:
                if marker not in self.order:
                    self.order.append(marker)
                self._inside[marker] = self._inside.get(marker, 0) + 1
                self.most_together = max(self.most_together, sum(1 for n in self._inside.values() if n))
            self.entered(marker).set()
            started = time.perf_counter()
            try:
                if marker in self.failing:
                    raise RuntimeError(f"analisi di {marker} fallita (doppio del test)")
                if marker in self.held:
                    _quiet_wait(self._event(self._released, marker), _HOLD_LIMIT_S)
                if self.pause_s:
                    time.sleep(self.pause_s)
                return function(html, *args, **kwargs)
            finally:
                with self._record:
                    self._inside[marker] -= 1
                    self.spans.append((marker, started, time.perf_counter()))
        return analysis


class _TurnWaits:
    """Osserva le attese (`threading.Event.wait`, `threading.Condition.wait`, con o senza scadenza) nel thread che ha
    appena scaricato una pagina con un marcatore, cioè l'attesa del turno di quel corpo: segnala quando comincia
    (`started`). Per i marcatori in `late` un'attesa `Event.wait` a tempo che scade resta ferma (`paused`) finché
    `resume()` per quel marcatore, o per tutti, come un thread che riprende in ritardo; per quelli in `fail_before`
    l'attesa solleva subito, per quelli in `fail_after` solleva appena il turno arriva. `fail()` aggiunge un
    marcatore a `fail_before`: la sua prossima attesa solleva."""

    def __init__(self, monkeypatch, late=(), fail_before=(), fail_after=()):
        self.late, self.fail_before, self.fail_after = set(late), set(fail_before), set(fail_after)
        self._events, self._record = {}, threading.Lock()
        monkeypatch.setattr(threading.Event, "wait", self._hook(threading.Event.wait, can_pause=True))
        monkeypatch.setattr(threading.Condition, "wait", self._hook(threading.Condition.wait, can_pause=False))

    def _event(self, kind, marker):
        with self._record:
            return self._events.setdefault((kind, marker), threading.Event())

    def started(self, marker):
        return self._event("started", marker)

    def paused(self, marker):
        return self._event("paused", marker)

    def fail(self, marker):
        self.fail_before.add(marker)

    def resume(self, *markers):
        for marker in markers or self.late:
            self._event("resume", marker).set()

    def _hook(self, original, can_pause):
        # Anche le attese senza scadenza. Solo `Event.wait` può restare ferma dopo la scadenza: `Condition.wait`
        # ritorna con il lock della condizione preso, e trattenerla lì fermerebbe anche chi deve consegnare il turno.
        def wait(waitable, timeout=None):
            marker = getattr(_TURN_THREAD, "marker", None)
            if marker is None or _QUIET.active:
                return original(waitable, timeout)
            _QUIET.active = True
            try:
                self.started(marker).set()
                if marker in self.fail_before:
                    raise RuntimeError("attesa del turno interrotta (doppio del test)")
                result = original(waitable, timeout)
                if result and marker in self.fail_after:
                    raise RuntimeError("attesa del turno interrotta alla consegna (doppio del test)")
                if not result and can_pause and marker in self.late:
                    self.paused(marker).set()
                    self._event("resume", marker).wait(_HOLD_LIMIT_S)
                return result
            finally:
                _QUIET.active = False
        return wait


class _TurnClock:
    """L'orologio del turno (`_turn_clock` del servizio) in mano al test: l'età di un corpo in coda cambia solo quando
    il test lo fa avanzare, quindi l'invecchiamento si prova senza aspettare e senza dipendere dal carico."""

    def __init__(self, monkeypatch):
        self.now = 1000.0
        monkeypatch.setattr(http_fingerprint, _CLOCK, lambda: self.now, raising=False)

    def advance(self, seconds):
        self.now += seconds


class _Request:
    """Una GET /http in un thread, con la sua durata (un solo URL, salvo `check_www`)."""

    def __init__(self, client, domain, check_www=False):
        self.domain, self.response, self.error, self.elapsed = domain, None, None, None
        started = time.perf_counter()

        def run():
            try:
                self.response = client.get("/http", params={"domain": domain, "check_www": check_www})
            except Exception as exc:    # un thread che muore in silenzio lascerebbe il test senza spiegazione
                self.error = exc
            self.elapsed = time.perf_counter() - started

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def wait(self, seconds):
        self._thread.join(seconds)
        return self.elapsed is not None

    def analysed(self, pages=1):
        """Le pagine sono state scaricate e analizzate."""
        if self.response is None or self.response.status_code != 200:
            return False
        checks = self.response.json()["checks"]
        return sum(1 for c in checks if c["status_code"] == 200 and c["content_hash_canonical"]) == pages

    def describe(self):
        if self.error is not None:
            return f"{self.domain}: la richiesta è fallita con {self.error!r}"
        if self.elapsed is None:
            return f"{self.domain}: la richiesta non è finita"
        return f"{self.domain}: HTTP {self.response.status_code} in {self.elapsed:.2f} s"


def _serve_pages(site, *markers):
    for marker in markers:
        site.serve(f"{marker}.example", _readable_page(marker))


def _assert_no_wait_without_contention(client, site, gate, marker):
    """Una pagina che arriva quando nessun'altra è in analisi entra subito: il turno è libero. Un turno rimasto
    occupato la terrebbe ferma oltre `_ENTRY_S` (col turno stretto, fino alla valvola di sicurezza)."""
    _serve_pages(site, marker)
    later = _Request(client, f"{marker}.example")
    assert gate.entered(marker).wait(_ENTRY_S), (
        f"una pagina senza altre analisi in corso non è entrata nell'analisi in {_ENTRY_S} s: il turno è rimasto "
        "occupato")
    later.wait(30)
    assert later.analysed(), later.describe()


def _overlapping(spans, markers=None):
    """Le coppie di corpi (fra `markers`, o tutti) le cui analisi si sono sovrapposte nel tempo: per ogni corpo,
    dalla prima chiamata alla fine dell'ultima."""
    joined = {}
    for marker, start, end in spans:
        if markers is None or marker in markers:
            first, last = joined.get(marker, (start, end))
            joined[marker] = (min(first, start), max(last, end))
    ordered = sorted((span, marker) for marker, span in joined.items())
    return [(a, b) for (span_a, a), (span_b, b) in zip(ordered, ordered[1:], strict=False) if span_b[0] < span_a[1]]


def _first_of(*events, timeout):
    """Attende il primo degli eventi; True se uno è arrivato entro `timeout`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(_quiet_wait(event, 0.01) for event in events):
            return True
    return False


def _sized_page(marker, size):
    """Una pagina leggibile di esattamente `size` caratteri."""
    page = _readable_page(marker)
    end = "</body></html>"
    filler = size - len(page) - len("<p></p>")
    assert filler >= 0, f"{size} caratteri sono troppo pochi per la pagina di {marker}"
    return page[: -len(end)] + "<p>" + "testo " * (filler // 6) + "x" * (filler % 6) + "</p>" + end


def _queue(client, site, waits, pages):
    """Mette in coda per il turno le pagine di `pages` ({marcatore: corpo}), una dopo l'altra: ognuna parte quando la
    precedente aspetta il turno. Restituisce le richieste."""
    requests = []
    for marker, body in pages.items():
        site.serve(f"{marker}.example", body)
        requests.append(_Request(client, f"{marker}.example"))
        assert waits.started(marker).wait(10), f"{marker} non si è messa in attesa del turno"
    return requests


_FOUR_BODIES = tuple(f"corpo-quattro{n}" for n in range(4))


def _serve_four_bodies(site):
    """Una pagina diversa su ciascuno dei quattro URL di `corpo-quattro.example`; restituisce i marcatori."""
    bodies = list(_FOUR_BODIES)
    urls = ["http://corpo-quattro.example", "https://corpo-quattro.example", "http://www.corpo-quattro.example",
            "https://www.corpo-quattro.example"]
    for url, marker in zip(urls, bodies, strict=True):
        site.pages[url] = _readable_page(marker)
    return bodies


def _stuck_request(client, site, gate, waits):
    """Una `/http` coi quattro corpi di `_FOUR_BODIES`, tutti trattenuti da `gate`: il primo che prende il turno resta
    in analisi (il corpo bloccato), gli altri tre aspettano il turno. Restituisce la richiesta, il corpo bloccato e i
    tre fratelli."""
    bodies = _serve_four_bodies(site)
    four = _Request(client, "corpo-quattro.example", check_www=True)
    assert _first_of(*(gate.entered(marker) for marker in bodies), timeout=10), "nessun corpo della richiesta è entrato"
    stuck = next(marker for marker in bodies if gate.entered(marker).is_set())
    siblings = [marker for marker in bodies if marker != stuck]
    for marker in siblings:
        assert waits.started(marker).wait(10), f"{marker} non si è messo in attesa del turno"
    return four, stuck, siblings


def _turn_errors(caplog):
    """Gli errori che il servizio ha registrato col suo logger."""
    return [record for record in caplog.records
            if record.name == http_fingerprint.logger.name and record.levelno >= logging.ERROR]


# ── Tetto alle liste degli elementi nascosti ──────────────────────────────────────────────────

_CAP = 100
_MANY = 237
# Un separatore di almeno 30 caratteri prima del base64: il contesto che il rilevatore ne riporta (i 30 caratteri
# precedenti) è sempre il separatore, quindi ogni elemento dipende solo dalla propria unità.
_SEP = "<p>separatore fisso di trenta caratteri.</p>"

# Un'unità per ciascuna lista, numerata: elementi distinti permettono di verificare quali sono rimasti e in che
# ordine. Ogni unità è chiusa in sé, quindi la pagina con le unità da 0 a n dà la concatenazione delle liste delle
# sue parti.
_UNITS = {
    "hidden_inputs": lambda i: f'<input type="hidden" name="campo{i}" value="valore{i}">',
    "hidden_forms": lambda i: f'<form style="display:none" action="https://raccolta.example/f/{i}"></form>',
    "invisible_iframes": lambda i: f'<iframe src="https://cornice.example/i/{i}" width="0" height="0"></iframe>',
    "tracking_pixels": lambda i: f'<img src="https://pixel.example/p/{i}.gif" width="1" height="1">',
    "meta_redirects": lambda i: f'<meta http-equiv="refresh" content="0;url=https://altrove.example/m/{i}">',
    "obfuscated_js": lambda i: f"<script>eval(atob('c2NyaXB0{i}'));</script>",
    "hidden_divs_with_content": lambda i: (f'<div style="display:none">testo nascosto numero {i:05d} '
                                           'con contenuto</div>'),
    "large_comments": lambda i: f"<!-- <div>{i:05d} " + "x" * 200 + " --> ",
    "base64_content": lambda i: _SEP + f"atob('{'QUJD' * 30}{i:05d}')",
}


def _mixed_unit(i):
    return "".join(unit(i) for unit in _UNITS.values())


def _page(unit, start, stop=None):
    """Pagina con le unità da `start` a `stop` escluso (con un solo argomento: da 0 a `start`)."""
    if stop is None:
        start, stop = 0, start
    return "<html><body>" + "".join(unit(i) for i in range(start, stop)) + "</body></html>"


@functools.lru_cache(maxsize=None)
def _hidden(name, start, stop):
    """`detect_hidden_elements` della pagina con le unità di `name` da `start` a `stop`. In cache perché più test
    leggono la stessa analisi (nessuno la modifica): il modulo deve restare breve."""
    return detect_hidden_elements(_page(_UNITS[name], start, stop), self_domain=_SITE)


def _findings(name, count):
    """Gli elementi di `name` per le unità da 0 a `count`, ricavati da pagine che ne hanno al più 100 (quindi
    intere): ciò che la lista completa conterrebbe senza tetto."""
    found = []
    for start in range(0, count, _CAP):
        found += _hidden(name, start, min(start + _CAP, count))[name]
    return found


def _is_subsequence(kept, full):
    remaining = iter(full)
    return all(any(item == candidate for candidate in remaining) for item in kept)


def _ints_outside(result, skip):
    """Gli interi del risultato fuori dalle chiavi `skip`, a ogni profondità."""
    stack = [v for k, v in result.items() if k not in skip]
    found = []
    while stack:
        value = stack.pop()
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            found.append(value)
        elif isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return found


# Rischio e `summary` della pagina con `n` elementi di una sola lista, come li dà l'analisi senza tetto.
_SIGNALS = {
    "hidden_inputs": (15, "{n} input nascosti — possibile form di raccolta dati"),
    "hidden_forms": (30, "{n} form nascosti — possibile credential harvesting"),
    "invisible_iframes": (25, "{n} iframe invisibili — possibile contenuto malevolo embedato"),
    "tracking_pixels": (10, "{n} pixel di tracking"),
    "meta_redirects": (20, "Meta refresh verso: https://altrove.example/m/0"),
    "obfuscated_js": (20, "{n} script offuscati — indicatori: eval, atob_base64"),
    "hidden_divs_with_content": (10, "{n} div nascosti con contenuto"),
    "large_comments": (15, "Commenti HTML con codice stageable — possibile kit in attesa di attivazione"),
    "base64_content": (15, "{n} blocchi base64 inline"),
}


def _signals(name, count):
    risk, summary = _SIGNALS[name]
    return risk, [summary.format(n=count)]


class TestHiddenElementListsAreCapped:
    @pytest.mark.parametrize("name", list(_UNITS))
    def test_a_list_longer_than_the_cap_keeps_one_hundred_findings_in_document_order(self, name):
        kept = _hidden(name, 0, _MANY).get(name, [])
        full = _findings(name, _MANY)

        assert len(full) == _MANY, f"la pagina di prova non produce {_MANY} elementi di {name}: {len(full)}"
        assert len(kept) == _CAP, f"{name}: {len(kept)} elementi su {_MANY} (tetto {_CAP})"
        assert _is_subsequence(kept, full), f"{name}: gli elementi tenuti non sono elementi della pagina, in ordine"

    @pytest.mark.parametrize("name", list(_UNITS))
    def test_a_list_of_exactly_one_hundred_findings_gives_the_unbounded_result(self, name):
        """Con 100 elementi il risultato è quello dell'analisi senza tetto: la lista intera, rischio e `summary`, e
        nient'altro. Le risorse esterne restano fuori dal confronto: il test non ne fissa l'ordine."""
        result = {k: v for k, v in _hidden(name, 0, _CAP).items() if k != "external_resources"}
        risk, summary = _signals(name, _CAP)
        expected = {name: _hidden(name, 0, 50)[name] + _hidden(name, 50, _CAP)[name],
                    "risk_indicators": risk, "summary": summary}

        assert result == expected, (
            f"{name}: con {_CAP} elementi il risultato non è quello senza tetto: chiavi {sorted(result)}, "
            f"{len(result.get(name, []))} elementi")

    @pytest.mark.parametrize("name", list(_UNITS))
    def test_risk_and_summary_are_those_of_the_whole_page(self, name):
        result = _hidden(name, 0, _MANY)

        assert (result["risk_indicators"], result["summary"]) == _signals(name, _MANY)

    @pytest.mark.parametrize("name", list(_UNITS))
    def test_the_full_count_of_a_list_can_be_read_from_the_result(self, name):
        """O la lista è intera, o il suo totale compare come numero nel risultato, fuori dalle liste: la dashboard e
        chi legge lo snapshot devono poter dire quanti erano."""
        result = _hidden(name, 0, _MANY)

        whole = len(result.get(name, [])) == _MANY
        assert whole or _MANY in _ints_outside(result, skip=set(_UNITS) | {"summary"}), (
            f"{name}: lista di {len(result.get(name, []))} elementi e nessun totale {_MANY} nel risultato: "
            f"{sorted(k for k in result if k not in _UNITS)}")

    def test_no_list_in_the_result_is_longer_than_the_cap(self):
        result = detect_hidden_elements(_page(_mixed_unit, _MANY), self_domain=_SITE)

        too_long = {k: len(v) for k, v in result.items() if isinstance(v, list) and len(v) > _CAP}
        assert not too_long, f"liste oltre {_CAP} elementi: {too_long}"


# ── Le scelte delle regex sostituite ──────────────────────────────────────────────────────────

_HIDDEN_TEXT = "testo nascosto abbastanza lungo da contare"

# Pagine in cui un tag offre più candidati alla stessa regex: (pagina, cosa se ne guarda, cosa ne ricava l'analisi
# senza tetto).
_CHOICES = {
    # Due `content=` nello stesso meta refresh: vale l'ultimo.
    "meta_two_contents": ('<meta http-equiv="refresh" content="0;url=https://primo.example/" '
                          'content="5;url=https://secondo.example/">',
                          "meta", [("5;url=https://secondo.example/", "https://secondo.example/", "5")]),
    # Due `style` che nascondono lo stesso div, il secondo con un `>` nel valore: il tag finisce dopo il secondo.
    "div_two_styles": (f'<div style="display:none" style="display:none;width:1px>0">{_HIDDEN_TEXT}</div>',
                       "divs", [(_HIDDEN_TEXT, 42)]),
    # Un `>` dentro il valore di `style`: il tag finisce dopo l'apice di chiusura.
    "div_gt_in_style": (f'<div style="width:1px>0;display:none">{_HIDDEN_TEXT}</div>', "divs", [(_HIDDEN_TEXT, 42)]),
    "div_two_classes": (f'<div class="hidden" class="x hidden>y">{_HIDDEN_TEXT}</div>', "divs", [(_HIDDEN_TEXT, 42)]),
    # Due `action` nello stesso form, due `type` nello stesso input: il campione arriva all'ultimo.
    "form_two_actions": ('<form action="/primo" action="/secondo" method="post"></form>',
                         "suspicious", {"<form[^>]*action": ['<form action="/primo" action']}),
    "input_two_types": ('<input type="password" name="p" type="password"><input type="email" name="e" type="email">',
                        "suspicious", {
                            r"<input[^>]*type=[\\\"']?password": ['<input type="password" name="p" type="password'],
                            r"<input[^>]*type=[\\\"']?email": ['<input type="email" name="e" type="email'],
                            "password|passwd|pwd": ["password", "password"]}),
    # `data:` seguito subito da `;base64,` non è un blocco base64; con un tipo in mezzo sì.
    "data_without_type": ('<img src="data:;base64,' + "QUJD" * 30 + '"><img src="data:image/png;base64,'
                          + "UVJT" * 30 + '">', "base64", [(120, "UVJTUVJT")]),
}


def _choice_view(view, html):
    if view == "suspicious":
        return {f["pattern"]: f["samples"] for f in detect_suspicious_patterns(html, DEFAULT_SUSPICIOUS_PATTERNS)}
    found = detect_hidden_elements(html, self_domain=_SITE)
    if view == "meta":
        return [(m["content"], m["target_url"], m["delay"]) for m in found.get("meta_redirects", [])]
    if view == "divs":
        return [(d["visible_text_preview"], d["text_length"]) for d in found.get("hidden_divs_with_content", [])]
    return [(b["length"], b["preview"][:8]) for b in found.get("base64_content", [])]


class TestTheChoicesOfTheReplacedPatternsAreKept:
    @pytest.mark.parametrize("case", list(_CHOICES))
    def test_a_tag_with_several_candidates_gives_the_expected_analysis(self, case):
        html, view, expected = _CHOICES[case]

        assert _choice_view(view, html) == expected


# ── Classificatore e dashboard leggono la pagina intera ───────────────────────────────────────

# Molti div nascosti senza form, poi uno con un form o con un solo input: l'elemento che decide l'alert del
# classificatore sta oltre la posizione 100.
_DECISIVE_DIVS = {
    "form": ('<div style="display:none"><form action="https://raccolta.example/x"><input name="utente"></form>'
             "contenuto iniettato nel sito del cliente</div>"),
    "input": '<div style="display:none"><input name="codice">contenuto iniettato nel sito del cliente</div>',
}


def _injected_page(kind):
    return ("<html><body>" + "".join(_UNITS["hidden_divs_with_content"](i) for i in range(150))
            + _DECISIVE_DIVS[kind] + "</body></html>")


_INJECTED_ALERTS = [
    ("legit_content_injected", "CRITICAL",
     "⚠ COMPROMISSIONE: contenuto nascosto con form iniettato su http://sito-cliente.example "
     "(dominio LEGITTIMO). Testo: contenuto iniettato nel sito del cliente"),
]

# Gli alert e il verdetto della pagina con 237 elementi di ogni lista, come li dà l'analisi senza tetto: i messaggi
# che leggono il primo elemento di una lista (indicatori, destinazione del redirect) compresi.
_MIXED_LEGIT_ALERTS = [
    ("legit_hidden_form_detected", "CRITICAL",
     "⚠ COMPROMISSIONE: form nascosto rilevato su http://sito-cliente.example (dominio LEGITTIMO del "
     "cliente). Possibile web skimmer o credential harvesting iniettato."),
    ("legit_invisible_iframe_detected", "CRITICAL",
     "⚠ COMPROMISSIONE: iframe invisibile su http://sito-cliente.example (dominio LEGITTIMO). "
     "Possibile caricamento contenuto malevolo."),
    ("legit_obfuscated_js_detected", "CRITICAL",
     "⚠ COMPROMISSIONE: JavaScript offuscato su http://sito-cliente.example (dominio LEGITTIMO). "
     "Indicatori: eval, atob_base64"),
    ("legit_meta_redirect_detected", "CRITICAL",
     "⚠ COMPROMISSIONE: meta redirect nascosto su http://sito-cliente.example (dominio LEGITTIMO) "
     "verso https://altrove.example/m/0. Possibile hijack."),
]

_MIXED_LOOKALIKE_VERDICT = {
    "auto_classification": "suspicious",
    "confidence": "high",
    "rule": "hidden_elements_detected",
    "rationale": ("Tag nascosti ad alto rischio (100/100): 237 form nascosti — possibile credential harvesting; "
                  "237 iframe invisibili — possibile contenuto malevolo embedato; 237 script offuscati — "
                  "indicatori: eval, atob_base64"),
}


def _diff_on_legit(client, site, html):
    """Gli alert del classificatore per il dominio legittimo che passa da nessun elemento nascosto a `html`."""
    site.serve(_LEGIT, html)
    current = {"dns": None, "cert": None, "whois": None, "reputation": None,
               "http": _http(client, _LEGIT, check_www=False).json()}
    baseline = {**current, "http": {"checks": [{"url": f"http://{_LEGIT}", "status_code": 200,
                                                "hidden_elements": {"risk_indicators": 0, "summary": []}}]}}
    response = baseline_diff(DiffInput(domain=_LEGIT, client="cliente", legitimate=_LEGIT,
                                       baseline=baseline, current=current))
    return [(a["type"], a["severity"], a["message"]) for a in json.loads(response.body)["alerts"]]


def _intel_tabs(client, site, pixel_pages):
    """La scheda Intel (node, script vero della dashboard) di un sosia per ogni pagina di `pixel_pages`
    ({nome: numero di pixel}), con la sezione http presa da `/http`."""
    node = shutil.which("node")
    if node is None:
        if os.environ.get("DOMAINSENTRY_REQUIRE_NODE") == "1":
            pytest.fail("node non disponibile ma DOMAINSENTRY_REQUIRE_NODE=1 lo richiede", pytrace=False)
        pytest.skip("node non disponibile: la resa della dashboard non si può eseguire")
    cases = []
    for name, count in pixel_pages.items():
        site.serve(_LOOKALIKE, _page(_UNITS["tracking_pixels"], count))
        http = _http(client, _LOOKALIKE, check_www=False).json()
        cases.append({"name": name, "domain": _LOOKALIKE, "client": "cliente", "updated_at": http["timestamp"],
                      "history": [], "intel": {"dns": None, "cert": None, "whois": None, "reputation": None,
                                               "http": http}})
    proc = subprocess.run([node, str(_ROOT / "tests" / "dashboard_render.js")], capture_output=True,
                          input=json.dumps({"cases": cases}), encoding="utf-8", timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr[-800:]
    rendered = json.loads(proc.stdout)
    assert rendered["load_error"] is None, rendered["load_error"]
    return {name: rendered["cases"][name]["intel_tab"] or "" for name in pixel_pages}


class TestClassifierAndDashboardSeeTheWholePage:
    @pytest.mark.parametrize("kind", list(_DECISIVE_DIVS))
    def test_a_div_with_a_form_or_an_input_beyond_the_cap_still_raises_the_injected_content_alert(
            self, site, http_client, kind):
        assert _diff_on_legit(http_client, site, _injected_page(kind)) == _INJECTED_ALERTS

    @pytest.mark.parametrize("kind", list(_DECISIVE_DIVS))
    def test_the_div_that_decides_the_alert_takes_a_place_in_the_list_not_an_extra_one(self, kind):
        kept = detect_hidden_elements(_injected_page(kind), self_domain=_LEGIT)["hidden_divs_with_content"]
        full = (_findings("hidden_divs_with_content", 150)
                + detect_hidden_elements(_DECISIVE_DIVS[kind], self_domain=_LEGIT)["hidden_divs_with_content"])

        assert len(kept) == _CAP, f"{len(kept)} div nascosti nella lista (tetto {_CAP})"
        assert _is_subsequence(kept, full), "i div tenuti non sono div della pagina, in ordine"

    def test_alerts_for_a_page_with_every_list_beyond_the_cap_are_those_of_the_whole_page(self, site, http_client):
        assert _diff_on_legit(http_client, site, _page(_mixed_unit, _MANY)) == _MIXED_LEGIT_ALERTS

    def test_the_verdict_on_a_lookalike_with_every_list_beyond_the_cap_is_that_of_the_whole_page(
            self, site, http_client):
        site.serve(_LOOKALIKE, _page(_mixed_unit, _MANY))
        http = _http(http_client, _LOOKALIKE, check_www=False).json()
        verdict = json.loads(classifier.classify_variant(classifier.VariantInput(
            domain=_LOOKALIKE, fuzzer="replacement", http=http,
            dns={"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.dns.example"]}})).body)

        assert {k: verdict[k] for k in ("auto_classification", "confidence", "rule", "rationale")} \
            == _MIXED_LOOKALIKE_VERDICT

    def test_the_dashboard_shows_how_many_pixels_the_page_has(self, site, http_client):
        """La scheda Intel mostra «Tracking pixels (n)»: n è quello della pagina, non quello della lista tagliata."""
        tab = _intel_tabs(http_client, site, {"pixel": _MANY})["pixel"]
        shown = re.findall(r"Tracking pixels \(([^)]*)\)", tab)

        assert shown and str(_MANY) in shown[0], f"la scheda Intel mostra «Tracking pixels ({shown})», non {_MANY}"

    def test_the_dashboard_says_how_many_pixels_it_does_not_list(self, site, http_client):
        """Oltre il tetto la scheda Intel elenca 100 pixel e dice quanti altri ce ne sono («… +N more», come per le
        risorse esterne); con pochi pixel li elenca tutti e non lo dice."""
        tabs = _intel_tabs(http_client, site, {"tanti": _MANY, "pochi": 5})

        assert re.search(rf"\+\s*{_MANY - _CAP}\s+more", tabs["tanti"]), (
            f"la scheda Intel non dice «+{_MANY - _CAP} more» per {_MANY} pixel di cui {_CAP} elencati")
        assert "more" not in tabs["pochi"], "la scheda Intel dice «more» con 5 pixel tutti elencati"


# ── Dimensioni ────────────────────────────────────────────────────────────────────────────────

# Mezzo MiB.
_HTTP_RESPONSE_LIMIT = 512 * _KIB


def _classify_request(domain, http):
    """La richiesta che l'orchestratore manda a `/classify/variant` dopo `/http`, serializzata come la serializza
    `requests` (`json=`): separatori con spazio, non ASCII in escape."""
    return json.dumps({"domain": domain, "fuzzer": "replacement", "dns": None, "cert": None, "http": http,
                       "whois": None, "reputation": None, "collection_status": {}}).encode("utf-8")


class TestResponseSize:
    def test_http_response_does_not_grow_with_hidden_elements_beyond_the_cap(self, site, http_client):
        """Una pagina con ogni lista oltre il tetto: con il doppio degli elementi la risposta resta la stessa (a meno
        delle cifre dei totali), quindi una pagina da 2 MiB non la ingrandisce."""
        sizes = {}
        for count in (110, 220):
            site.serve(_SITE, _page(_mixed_unit, count))
            sizes[count] = len(_http(http_client, check_www=False).content)

        assert sizes[220] - sizes[110] <= 256, f"la risposta cresce con gli elementi oltre il tetto: {sizes} byte"

    def test_http_response_for_a_page_full_of_tracking_pixels_stays_under_half_a_mebibyte(self, site, http_client):
        """1.000 pixel 1x1 (~60 KiB) serviti su tutti e quattro gli URL di `/http`, come li serve un sosia."""
        site.serve(_SITE, _page(_UNITS["tracking_pixels"], 1000), everywhere=True)
        size = len(_http(http_client).content)

        assert size <= _HTTP_RESPONSE_LIMIT, f"risposta di /http di {size} byte (limite {_HTTP_RESPONSE_LIMIT})"

    def test_the_classification_request_for_a_page_full_of_hidden_divs_is_accepted(self, site, http_client):
        """1.200 div nascosti con testo (~90 KiB) sui quattro URL: la richiesta che l'orchestratore costruisce per
        `/classify/variant` resta sotto 1 MiB."""
        site.serve(_SITE, _page(_UNITS["hidden_divs_with_content"], 1200), everywhere=True)
        request = _classify_request(_SITE, _http(http_client).json())

        assert len(request) < MAX_BODY_SIZE, (
            f"richiesta a /classify/variant di {len(request)} byte (limite {MAX_BODY_SIZE})")
        with TestClient(classifier.app) as client:
            response = client.post("/classify/variant", content=request,
                                   headers={"Content-Type": "application/json"})
        assert response.status_code == 200, f"/classify/variant ha risposto {response.status_code}"
        assert response.json()["auto_classification"]


# ── Pagine leggibili: i risultati attesi ──────────────────────────────────────────────────────

def _readable_pages():
    """Pagine ben formate delle forme che la pipeline incontra: blog, accesso, clone di accesso, kit con
    redirezione, parcheggio, applicazione a pagina singola, negozio, pagina con markup morto."""
    articles = "".join(
        f'<article id="post-{i}"><h2><a href="/p/{i}">Articolo {i}</a></h2>'
        f'<p>Testo dell\'articolo numero {i}, con qualche parola in più per riempire il paragrafo.</p>'
        f'<img src="/img/{i}.jpg" width="640" height="480" alt=""></article>'
        for i in range(12))
    products = "".join(
        f'<div class="product"><img src="data:image/png;base64,{"iVBORw0KGgo" * 12}{i:03d}" alt="">'
        f'<h3>Prodotto {i}</h3><span class="price">{i * 7 + 5},99</span></div>' for i in range(6))
    return {
        "blog": ('<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><title>Blog &#8211; Esempio</title>'
                 '<script>window.settings={"ts":1714200000000,"v":"6.5.3"};</script>'
                 '<style>img.emoji{display:inline!important}</style></head><body class="home">'
                 '<!-- analytics --><script async src="https://statistiche.example/js?id=G-ABC"></script>'
                 '<header><nav><a href="/">Home</a> <a href="/contatti">Contatti</a></nav></header>'
                 f'<main>{articles}</main>'
                 '<div class="cookie-banner hidden" style="display:none">Usiamo i cookie per migliorare la '
                 'navigazione del sito.</div><footer>&copy; Esempio</footer></body></html>'),
        "login": ('<!DOCTYPE html><html><head><meta charset=utf-8><title>Accedi - Banca Esempio</title>'
                  '<style>body{font-family:sans-serif}</style><script>var t=1714200000000;</script></head><body>'
                  '<!-- build 5f4dcc3b5aa765d61d8327deb882cf99 --><div class=login><h1>Accedi</h1>'
                  '<form action="https://raccolta.example/post" method=post><input name=user>'
                  '<input type=password name=pwd><input type=hidden name=tok value=abc></form></div>'
                  '<img src="https://t.example/p.gif" width=1 height=1>'
                  '<div style="display:none">contenuto nascosto abbastanza lungo da superare venti caratteri</div>'
                  '</body></html>'),
        "login_clone": ('<!DOCTYPE html><html><head><title>Sign in to your account</title>'
                        '<style>.hide{display:none}</style></head><body><div class="login-page">'
                        '<form id="f" method="post" action="https://raccolta.example/post.php">'
                        '<input type="hidden" name="ctx" value="a1b2c3"><input type="hidden" name="flow" value="z9">'
                        '<input type="email" name="loginfmt" placeholder="Email"><input type=password name="passwd">'
                        '<input type="submit" value="Sign in"></form></div>'
                        '<div style="display:none"><form action="http://raccolta.example/c.php"><input name="u">'
                        '<input type="password" name="p"></form> modulo di raccolta credenziali preparato</div>'
                        '<iframe src="https://cornice.example/f" width="0" height="0" '
                        'style="visibility:hidden"></iframe>'
                        '<script>var _c="k";eval(atob("ZG9jdW1lbnQud3JpdGUoJ3gnKTs="));</script>'
                        '<!-- note di sviluppo --></body></html>'),
        "kit": ('<html><head><title>Online Banking</title><meta http-equiv="refresh" content="900;url=/timeout.php">'
                '</head><body><h1>Accedi al tuo conto</h1><form action="login.php" method="POST">'
                '<input type="text" name="username"><input type="password" name="password">'
                + "".join(f'<input type="hidden" name="h{i}" value="{i}">' for i in range(5)) +
                '</form><script>function init(){var _0x=["\\x68\\x74\\x74\\x70","\\x6c\\x6f\\x63\\x61\\x74\\x69\\x6f'
                '\\x6e","\\x68\\x72\\x65\\x66","\\x61\\x62"];document[_0x[1]]=_0x[0]}</script>'
                '<div class="stage hidden"><p>Inserisci il codice ricevuto via SMS per continuare.</p>'
                '<form action="otp.php"><input name="otp"></form></div><!-- '
                + "var s=document.createElement('script');s.src='http://kit.example/k.js';" * 4
                + ' --></body></html>'),
        "parking": ('<html><head><title>dominio.example</title></head><body><div id="p"><h1>Questo dominio è in '
                    'vendita</h1><p>Contatta il venditore per una proposta.</p>'
                    '<a href="https://mercato-domini.example/compra?d=x">Acquista</a></div>'
                    '<script>window.park={"ts":1714200000123,"id":"0123456789abcdef0123456789abcdef"};</script>'
                    '</body></html>'),
        "spa": ('<!doctype html><html><head><meta charset="utf-8"><title>App</title><link rel="icon" href="data:,">'
                '<script defer src="/static/js/main.1a2b3c4d.js"></script></head><body>'
                '<noscript>Serve JavaScript per usare questa applicazione.</noscript><div id="root"></div>'
                '</body></html>'),
        "redirect": ('<html><head><meta http-equiv=refresh content="0; url=https://atterraggio.example/l">'
                     '<title>Reindirizzamento</title></head><body><script>setTimeout(function(){'
                     'window.location="https://atterraggio.example/l"},100)</script><p>Reindirizzamento in corso</p>'
                     '</body></html>'),
        "shop": ('<html><head><title>Negozio</title><style>.product{float:left}</style></head><body>'
                 f'{products}<div style="display: none" class="modal">Offerta riservata ai clienti registrati '
                 'del negozio.</div></body></html>'),
        "dead_markup": ('<html><head><title>Video</title></head><body><iframe src="/video">'
                        '<img src="http://altrove.example/p.gif" width="1" height="1"></iframe>'
                        '<p>Guarda il video qui sopra.</p></body></html>'),
    }


# Titolo, rischio, `summary` e impronta completa dell'analisi di ogni pagina leggibile, come li dà l'analisi senza
# tetto (identici con Python 3.12 e 3.13 e con qualunque seme dell'hash).
_READABLE_EXPECTED = {
    "blog": {
        "title": "Blog &#8211; Esempio", "risk": 10, "signature": "dabacf86d0ec1967",
        "summary": [
            "2 div nascosti con contenuto",
        ],
    },
    "login": {
        "title": "Accedi - Banca Esempio", "risk": 20, "signature": "e5dcfcb38c91013d",
        "summary": [
            "1 pixel di tracking",
            "1 div nascosti con contenuto",
        ],
    },
    "login_clone": {
        "title": "Sign in to your account", "risk": 70, "signature": "2e3f75d904de1e5e",
        "summary": [
            "1 iframe invisibili — possibile contenuto malevolo embedato",
            "1 script offuscati — indicatori: eval, atob_base64",
            "Div nascosto contenente un form — alta probabilità di phishing preparato",
        ],
    },
    "kit": {
        "title": "Online Banking", "risk": 75, "signature": "e8a990317c8c19dc",
        "summary": [
            "Meta refresh verso: /timeout.php",
            "5 input nascosti — possibile form di raccolta dati",
            "Div nascosto contenente un form — alta probabilità di phishing preparato",
            "Commenti HTML con codice stageable — possibile kit in attesa di attivazione",
        ],
    },
    "parking": {
        "title": "dominio.example", "risk": 0, "signature": "151151bd23d86685",
        "summary": [],
    },
    "spa": {
        "title": "App", "risk": 0, "signature": "6461f3ede276f4ef",
        "summary": [],
    },
    "redirect": {
        "title": "Reindirizzamento", "risk": 20, "signature": "739538e7c98771b1",
        "summary": [
            "Meta refresh verso: None",
        ],
    },
    "shop": {
        "title": "Negozio", "risk": 25, "signature": "1ece876760f0526a",
        "summary": [
            "1 div nascosti con contenuto",
            "6 blocchi base64 inline",
        ],
    },
    "dead_markup": {
        "title": "Video", "risk": 30, "signature": "c5a9101a36038bc6",
        "summary": [
            "1 markup morti sospetti verso host esterno — mai renderizzati per costruzione",
        ],
    },
}

# Impronta (`_check_signature` sulle sole liste da regex) di ogni documento di `_corpus()`, nello stesso ordine.
_CORPUS_EXPECTED = (
    'd4efdcf7d37ec2ae', 'b7df1f9fa22d20c0', '730284d96ac766d2', 'aeb5e40ef1cba21c', '257199cb5a95163f',
    '2b4ced4dc22e7d0b', '2a19e39fe2b2c811', '9afbea8d5a6009ae', 'f54c3f57165adeaa', 'df22ffa7bf1c1308',
    '66dd755368a650b1', 'e6f505cb5eb3f063', '9d9c0173f557f62a', 'bd2a53d3317d5aec', '7f6bbc7ca578912d',
    'a555b893157111f4', 'b2adf1c4a2da0acc', '8e9bfd9620d8e051', '24852d507f89b1c8', '0b81adce8a258429',
    '4abb738e2bdfd995', '81113214fff0be40', 'dd5e4abce6c3dcc3', '41c1486eea58d940', '3be8124f066a5935',
    '35698838cf35c014', 'ef351c3dc0b9ded1', '2807bd635ba898c6', '46052c83922fa9d0', '0a039289ca60cf0d',
    'acd4917a9878635e', '1044bb4b8167fc0d', '432da4168dbd342f', '7f3dd4dd527c66ef', 'ee4744ddd332d7db',
    '9b8df9b8c1db1844', '33dbf0d91bb0cd0f', '7818f03dfd5115ab', '42488196aa791213', '5fd777b4e40e5726',
    '4e14b538e9808b25', 'f7decc3745a73edc', 'b621f1ff822883c4', '8ab7ae082904398a', '25faa9963e176d29',
    'f6342a8edc914f1a', 'a524df47042747cc', '1b41453c7b7a5daa', '1265ba2684654c0d', '5eaf5e351cf23050',
    '07bdbf9db6c20678', '3ec7143eced36d69', '9ce5bdef54ce2413', '6e4c7d965b7befd7', 'b8a752afa7f18100',
    '4394ec47ea0bae5e', '0540c13b80941cc1', '9c00a3804a06c611', '5a7accbb1ef63905', 'd3b154a0d2d3112e',
    '13222888cfa1820c', 'd764b4085fbcb696', 'f36dbff98dd947cb', 'a8b476fa219c141f', '9135fb2b9ed1b1dd',
    '0281a1e49a713ad8', 'adf68cc024647c3f', '9d1aad9307ae44eb', '3265cb085c1bd665', '2b8887fb46bbcfbf',
    'd7d70f547eab7b83', 'b94cbcfd2636dcd0', 'dfd3ec5548648476', '86f965c982a87233', '63bd64b4d670cb2b',
    'f9422b570d402fd0', '8598b7ca8104f9ad', '9c3a27278dbb0d86', '9ecb1bd801537940', 'fd39a8be0d2649f4',
)


def _check_signature(check, keys=None):
    """Impronta di ciò che l'analisi produce per una pagina: titolo, hash della forma normalizzata e del testo
    visibile, pattern sospetti ed elementi nascosti (le risorse esterne ordinate, così il confronto non dipende dal
    loro ordine). Con `keys`, solo quelle chiavi degli elementi nascosti."""
    hidden = dict(check["hidden_elements"] or {})
    if "external_resources" in hidden:
        hidden["external_resources"] = sorted(hidden["external_resources"])
    if keys is not None:
        hidden = {k: v for k, v in hidden.items() if k in keys}
    blob = json.dumps({"title": check["title"], "canonical": check["content_hash_canonical"],
                       "visible": check["visible_text_hash"], "suspicious": check["suspicious_patterns"],
                       "hidden": hidden}, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# Le liste degli elementi nascosti ricavate da regex. Quelle ricavate dal parser HTML della libreria standard
# (form, iframe, pixel, markup morto, input nascosti da CLS-01u, quindi anche rischio e `summary`) restano fuori
# dal corpus casuale: sul markup malformato il parser cambia fra una versione di Python e l'altra.
_REGEX_LISTS = ("meta_redirects", "obfuscated_js", "hidden_divs_with_content", "large_comments", "base64_content",
                "external_resources")

_FRAGMENTS = [
    "<script>", "</script>", "<SCRIPT type=text/javascript>", "</script >", "<style>", "</style>", "<!--", "-->",
    "--!>", "<title>", "</title>", "<title ", "<", ">", "<<", "</", "<!", "<?xml ", "<p>", "</p>", "<b>",
    "<form ", "<form action=x>", "</form>", '<form style="display:none" action="https://raccolta.example/f">',
    "<input ", "<input type=hidden name=a value=b>", "<input type=password>", '<input type="email" name=e>',
    "<meta http-equiv=refresh content=0;url=http://altrove.example/>", "<meta ", "http-equiv=refresh ",
    "content=", '<div style="display:none">', '<div style="visibility:hidden">', '<div class="x hidden">',
    "<div ", "<div>", "</div>", '"', "'", "=", " ", "\n", "testo visibile di prova abbastanza lungo",
    "login", "password", "username", "accedi", "data:image/png;base64,", "QUJD" * 30, "atob('", "')", "eval(",
    "atob(", "\\x41" * 12, "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22]", "1714200000000",
    "0123456789abcdef0123456789abcdef", 'src="http://esterno.example/a.js"', 'href=https://esterno.example/b',
    "function f(){document.write(1)}", "x" * 210,
]


def _corpus(seed=47, count=80):
    """Documenti casuali dai frammenti sopra, a seme fisso: costrutti chiusi e non chiusi mescolati."""
    rng = random.Random(seed)
    return ["".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(5, 80))) for _ in range(count)]


def _analyse(client, site, html, domain=_SITE):
    site.serve(domain, html)
    [check] = _active_checks(_http(client, domain, check_www=False))
    return check


class TestReadablePagesGiveTheExpectedAnalysis:
    @pytest.mark.parametrize("name", list(_readable_pages()))
    def test_a_readable_page_gives_the_expected_analysis(self, site, http_client, name):
        check = _analyse(http_client, site, _readable_pages()[name])
        hidden = check["hidden_elements"] or {}
        got = {"title": check["title"], "risk": hidden.get("risk_indicators"), "summary": hidden.get("summary"),
               "signature": _check_signature(check)}

        assert got == _READABLE_EXPECTED[name], json.dumps(check, ensure_ascii=False)[:3000]

    def test_a_seeded_corpus_of_mixed_markup_gives_the_expected_analysis(self, site, http_client):
        got = [_check_signature(_analyse(http_client, site, html), keys=_REGEX_LISTS) for html in _corpus()]

        differing = [i for i, (a, b) in enumerate(zip(got, _CORPUS_EXPECTED, strict=True)) if a != b]
        assert not differing, (
            f"{len(differing)} documenti su {len(got)} analizzati diversamente; il primo è il n. {differing[0]} di "
            f"`_corpus()`: {_corpus()[differing[0]][:300]!r}")


# ── Il turno dell'analisi: garanzie ───────────────────────────────────────────────────────────

# Ultima classe del modulo. Col turno stretto un servizio che perde il turno lascerebbe in attesa ogni analisi
# successiva fino alla valvola di sicurezza: ogni test della classe usa un turno nuovo (`_fresh_turn`), così il danno
# resta nel test che lo causa.
class TestTheAnalysisTurnIsFairAndBounded:
    @pytest.fixture(autouse=True)
    def _fresh_turn(self, monkeypatch):
        monkeypatch.setattr(http_fingerprint, "_ANALYSIS_TURN", type(http_fingerprint._ANALYSIS_TURN)())

    def test_a_page_waits_for_its_turn_however_long_another_analysis_lasts(self, site, http_client, monkeypatch):
        """Mentre l'analisi di un corpo resta in corso, la pagina di un altro dominio aspetta il turno e non entra
        nell'analisi accanto a lei, per quanto aspetti sotto la valvola di sicurezza: né un'attesa massima
        `ANALYSIS_MAX_WAIT_S` di un centesimo di secondo, né l'invecchiamento, con l'orologio del turno avanti di
        59 s, la fanno entrare. Finita l'analisi trattenuta entra lei, e dopo il turno è libero."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _AGING, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {"corpo-attesa": _readable_page("corpo-attesa")})
            clock.advance(59)
            alongside = _first_of(gate.entered("corpo-attesa"), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert not alongside, "la pagina in attesa è entrata nell'analisi mentre un'altra era in corso"
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.most_together == 1, f"{gate.most_together} corpi analizzati insieme"
        _assert_no_wait_without_contention(http_client, site, gate, "corpo-dopo")

    def test_the_shortest_waiting_page_enters_the_analysis_first(self, site, http_client, monkeypatch):
        """Tre pagine arrivano, dalla più lunga alla più corta, mentre un'analisi è in corso: entrano dalla più corta
        alla più lunga, una alla volta. L'orologio del turno è fermo: nessuna invecchia."""
        monkeypatch.setattr(http_fingerprint, _AGING, 3600.0, raising=False)
        _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        pages = {"corpo-lungo": _sized_page("corpo-lungo", 24 * _KIB),
                 "corpo-medio": _sized_page("corpo-medio", 8 * _KIB),
                 "corpo-corto": _sized_page("corpo-corto", 2 * _KIB)}
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, pages)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-lento", "corpo-corto", "corpo-medio", "corpo-lungo"], (
            f"ordine di ingresso nell'analisi: {gate.order} (arrivate dalla più lunga alla più corta)")
        assert gate.most_together == 1, f"{gate.most_together} corpi analizzati insieme"

    def test_pages_of_equal_length_enter_the_analysis_in_arrival_order(self, site, http_client, monkeypatch):
        """Tre pagine della stessa lunghezza arrivano una dopo l'altra mentre un'analisi è in corso: entrano
        nell'analisi in quell'ordine. Ognuna parte quando la precedente è in attesa del turno; l'orologio del turno
        è fermo."""
        monkeypatch.setattr(http_fingerprint, _AGING, 3600.0, raising=False)
        _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        pages = {marker: _readable_page(marker) for marker in ("corpo-uno", "corpo-due", "corpo-tre")}
        assert len({len(page) for page in pages.values()}) == 1
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, pages)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-lento", *pages], f"ordine di ingresso nell'analisi: {gate.order}"

    def test_a_page_with_no_other_analysis_in_progress_does_not_wait(self, site, http_client):
        """Senza altre analisi in corso il turno è libero: nessuna attesa, con l'attesa massima del servizio."""
        site.serve("corpo-solo.example", _readable_page("corpo-solo"))
        alone = _Request(http_client, "corpo-solo.example")
        alone.wait(30)

        assert alone.analysed(), alone.describe()
        assert alone.elapsed < _WAIT_MARGIN_S, f"la pagina ha atteso {alone.elapsed:.2f} s senza altre analisi"

    def test_a_page_that_has_waited_the_aging_time_enters_before_shorter_pages_that_arrived_after_it(
            self, site, http_client, monkeypatch):
        """Una pagina lunga è in coda. Finché non ha atteso `ANALYSIS_AGING_S`, una pagina più corta arrivata dopo di
        lei la supera; dopo, un'altra pagina più corta arrivata dopo di lei non la supera più: entra la lunga, da
        sola, e poi la corta. È il limite all'attesa di ogni pagina."""
        aging = 30.0
        monkeypatch.setattr(http_fingerprint, _AGING, aging, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-lento", "corpo-corto1", "corpo-lungo"})
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.entered("corpo-lento").wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {"corpo-lungo": _sized_page("corpo-lungo", 24 * _KIB)})
            clock.advance(1)
            requests += _queue(http_client, site, waits, {"corpo-corto1": _sized_page("corpo-corto1", 2 * _KIB)})
            clock.advance(1)           # la lunga aspetta da 2 s: non è invecchiata
            gate.release("corpo-lento")
            assert _first_of(gate.entered("corpo-corto1"), gate.entered("corpo-lungo"), timeout=10), (
                "nessuna pagina in coda è entrata dopo l'analisi trattenuta")
            requests += _queue(http_client, site, waits, {"corpo-corto2": _sized_page("corpo-corto2", 2 * _KIB)})
            clock.advance(aging - 1)   # la lunga aspetta da 31 s, la seconda corta da 29 s
            gate.release("corpo-corto1")
            assert _first_of(gate.entered("corpo-lungo"), timeout=10), "la pagina lunga non è entrata"
            alongside = _first_of(gate.entered("corpo-corto2"), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-lento", "corpo-corto1", "corpo-lungo", "corpo-corto2"], (
            f"ordine di ingresso nell'analisi: {gate.order}")
        assert not alongside, "una pagina più corta è entrata accanto alla pagina invecchiata"
        assert gate.most_together == 1, f"{gate.most_together} corpi analizzati insieme"

    def test_pages_that_have_waited_the_aging_time_enter_in_arrival_order_before_a_younger_shorter_page(
            self, site, http_client, monkeypatch):
        """Due pagine hanno atteso più di `ANALYSIS_AGING_S`, la più lunga arrivata per prima; una terza, più corta,
        è appena arrivata: entrano le due in ordine d'arrivo, poi la terza."""
        aging = 30.0
        monkeypatch.setattr(http_fingerprint, _AGING, aging, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {"corpo-lungo": _sized_page("corpo-lungo", 24 * _KIB)})
            clock.advance(1)
            requests += _queue(http_client, site, waits, {"corpo-medio": _sized_page("corpo-medio", 8 * _KIB)})
            clock.advance(aging + 5)   # 36 s e 35 s di attesa
            requests += _queue(http_client, site, waits, {"corpo-corto": _sized_page("corpo-corto", 2 * _KIB)})
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-lento", "corpo-lungo", "corpo-medio", "corpo-corto"], (
            f"ordine di ingresso nell'analisi: {gate.order}")
        assert gate.most_together == 1, f"{gate.most_together} corpi analizzati insieme"

    def test_the_aging_time_is_ten_seconds(self):
        """Il limite all'attesa: una pagina in coda da più di `ANALYSIS_AGING_S` non è più superata da quelle arrivate
        dopo di lei, quindi aspetta al più questo tempo più le analisi delle pagine che aveva davanti."""
        assert getattr(http_fingerprint, _AGING, None) == 10, (
            f"`{_AGING}` in services/http_fingerprint.py: {getattr(http_fingerprint, _AGING, None)!r}")

    def test_a_turn_held_longer_than_the_stuck_time_passes_to_the_next_page_and_is_logged(
            self, site, http_client, monkeypatch, caplog):
        """Valvola di sicurezza: chi tiene il turno da più di `ANALYSIS_STUCK_S` (letta a ogni controllo, qui 120 s
        sull'orologio del turno) lo perde e il turno passa alla pagina in coda; prima della soglia no, nemmeno oltre i
        60 s predefiniti. Il passaggio è registrato con un errore che non riporta dati della pagina."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 120.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-bloccato")
        waits = _TurnWaits(monkeypatch)
        caplog.set_level(logging.ERROR, logger=http_fingerprint.logger.name)
        _serve_pages(site, "corpo-bloccato")
        requests = [_Request(http_client, "corpo-bloccato.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {"corpo-attesa": _readable_page("corpo-attesa")})
            clock.advance(100)
            early = _first_of(gate.entered("corpo-attesa"), timeout=_ALONGSIDE_S)
            clock.advance(21)          # il turno è tenuto da 121 s
            passed = _first_of(gate.entered("corpo-attesa"), timeout=_VALVE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert not early, "il turno è passato prima che chi lo teneva superasse `ANALYSIS_STUCK_S`"
        assert passed, f"oltre `ANALYSIS_STUCK_S` la pagina in coda non è entrata entro {_VALVE_S} s"
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        errors = _turn_errors(caplog)
        assert errors, "il passaggio del turno da parte della valvola non è registrato come errore"
        text = " ".join(record.getMessage() for record in errors)
        assert "corpo-" not in text and ".example" not in text, f"l'errore riporta dati della pagina: {text!r}"

    def test_a_stuck_page_that_ends_after_the_valve_does_not_pass_the_turn_again(self, site, http_client, monkeypatch):
        """La valvola passa il turno da una pagina bloccata alla prima in coda; poi la pagina bloccata finisce e non
        ripassa un turno che non ha più: la seconda in coda aspetta finché la prima ha il turno, poi entra, e dopo il
        turno è libero."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-bloccato", "corpo-uno"})
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-bloccato")
        stuck = _Request(http_client, "corpo-bloccato.example")
        requests = [stuck]
        try:
            assert gate.entered("corpo-bloccato").wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {marker: _readable_page(marker)
                                                          for marker in ("corpo-uno", "corpo-due")})
            clock.advance(61)
            assert _first_of(gate.entered("corpo-uno"), gate.entered("corpo-due"), timeout=_VALVE_S), (
                "oltre `ANALYSIS_STUCK_S` nessuna pagina in coda è entrata")
            gate.release("corpo-bloccato")
            assert stuck.wait(30), "la pagina bloccata non è finita dopo essere stata sbloccata"
            alongside = _first_of(gate.entered("corpo-due"), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert not alongside, ("finita la pagina bloccata, una seconda pagina è entrata mentre la prima aveva il "
                               "turno: il turno è stato passato due volte")
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-bloccato", "corpo-uno", "corpo-due"], f"ordine di ingresso: {gate.order}"
        _assert_no_wait_without_contention(http_client, site, gate, "corpo-dopo")

    def test_the_safety_valve_gives_the_turn_to_a_page_that_has_waited_the_aging_time_first(
            self, site, http_client, monkeypatch):
        """Quando la valvola scatta, il turno va a chi l'ordine normale designa: una pagina lunga che ha atteso più di
        `ANALYSIS_AGING_S` prima di due più corte appena arrivate, e da sola; poi le due, la più corta per prima."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 120.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _AGING, 10.0, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-bloccato", "corpo-lungo"})
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-bloccato")
        requests = [_Request(http_client, "corpo-bloccato.example")]
        try:
            assert gate.entered("corpo-bloccato").wait(10), "l'analisi trattenuta non è cominciata"
            requests += _queue(http_client, site, waits, {"corpo-lungo": _sized_page("corpo-lungo", 24 * _KIB)})
            clock.advance(115)         # la lunga aspetta da 115 s
            requests += _queue(http_client, site, waits, {"corpo-medio": _sized_page("corpo-medio", 8 * _KIB),
                                                          "corpo-corto": _sized_page("corpo-corto", 2 * _KIB)})
            clock.advance(6)           # turno tenuto da 121 s; le due appena arrivate aspettano da 6 s
            pages = ("corpo-lungo", "corpo-medio", "corpo-corto")
            assert _first_of(*(gate.entered(m) for m in pages), timeout=_VALVE_S), (
                "oltre `ANALYSIS_STUCK_S` nessuna pagina in coda è entrata")
            first = [m for m in pages if gate.entered(m).is_set()]
            alongside = _first_of(*(gate.entered(m) for m in pages if m not in first), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert first == ["corpo-lungo"], f"la valvola ha fatto entrare {first}"
        assert not alongside, "una pagina è entrata accanto a quella designata dalla valvola"
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-bloccato", "corpo-lungo", "corpo-corto", "corpo-medio"], (
            f"ordine di ingresso: {gate.order}")

    def test_the_safety_valve_gives_the_turn_to_the_shortest_page_when_none_has_aged(
            self, site, http_client, monkeypatch):
        """Nessuna pagina in coda ha atteso `ANALYSIS_AGING_S`: la valvola dà il turno alla più corta, da sola."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 120.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _AGING, 10.0, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-bloccato", "corpo-corto"})
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-bloccato")
        requests = [_Request(http_client, "corpo-bloccato.example")]
        try:
            assert gate.entered("corpo-bloccato").wait(10), "l'analisi trattenuta non è cominciata"
            clock.advance(115)
            requests += _queue(http_client, site, waits, {"corpo-lungo": _sized_page("corpo-lungo", 24 * _KIB),
                                                          "corpo-corto": _sized_page("corpo-corto", 2 * _KIB)})
            clock.advance(6)           # turno tenuto da 121 s; le due aspettano da 6 s
            passed = _first_of(gate.entered("corpo-corto"), timeout=_VALVE_S)
            alongside = _first_of(gate.entered("corpo-lungo"), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert passed, "oltre `ANALYSIS_STUCK_S` la pagina più corta non è entrata"
        assert not alongside, "la pagina lunga è entrata accanto a quella designata dalla valvola"
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert gate.order == ["corpo-bloccato", "corpo-corto", "corpo-lungo"], f"ordine di ingresso: {gate.order}"

    def test_the_stuck_time_is_sixty_seconds(self):
        """La valvola scatta solo per un difetto: un'analisi di un corpo da 2 MiB dura al più pochi secondi."""
        assert getattr(http_fingerprint, _STUCK, None) == 60, (
            f"`{_STUCK}` in services/http_fingerprint.py: {getattr(http_fingerprint, _STUCK, None)!r}")

    def test_the_safety_valve_gives_the_turn_to_another_request_not_to_a_sibling_of_the_stuck_body(
            self, site, http_client, monkeypatch):
        """Un corpo di una `/http` da quattro resta bloccato col turno; i suoi tre fratelli, più corti, e una pagina di
        un'altra richiesta aspettano. Alla valvola entra la pagina dell'altra richiesta, non un fratello: un fratello
        aspetterebbe il turno della propria richiesta tenendo quello condiviso."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held=set(_FOUR_BODIES))
        waits = _TurnWaits(monkeypatch)
        requests = []
        try:
            four, stuck, siblings = _stuck_request(http_client, site, gate, waits)
            requests.append(four)
            requests += _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB)})
            clock.advance(61)
            passed = _first_of(gate.entered("corpo-estraneo"), timeout=_VALVE_S)
            alongside = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert passed, (f"oltre `ANALYSIS_STUCK_S` la pagina di un'altra richiesta non è entrata entro {_VALVE_S} s: "
                        "il turno è andato a un fratello del corpo bloccato")
        assert not alongside, "un fratello del corpo bloccato è entrato nell'analisi accanto a lui"
        assert all(r.analysed(pages=4 if r is requests[0] else 1) for r in requests), [r.describe() for r in requests]

    def test_with_only_siblings_of_the_stuck_body_waiting_the_safety_valve_waits_for_another_request(
            self, site, http_client, monkeypatch, caplog):
        """Un corpo resta bloccato col turno e aspettano solo i suoi fratelli: la valvola non passa il turno e non
        registra nulla, a ogni controllo. Quando arriva una pagina di un'altra richiesta, la valvola le passa il turno
        al primo controllo e lo registra una volta sola."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held=set(_FOUR_BODIES))
        waits = _TurnWaits(monkeypatch)
        caplog.set_level(logging.ERROR, logger=http_fingerprint.logger.name)
        requests = []
        try:
            four, stuck, siblings = _stuck_request(http_client, site, gate, waits)
            requests.append(four)
            clock.advance(61)
            entered = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ALONGSIDE_S)
            logged_with_only_siblings = len(_turn_errors(caplog))
            requests += _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB)})
            passed = _first_of(gate.entered("corpo-estraneo"), timeout=_VALVE_S)
            logged_after = len(_turn_errors(caplog))
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert not entered, "un fratello del corpo bloccato è entrato nell'analisi accanto a lui"
        assert logged_with_only_siblings == 0, (
            f"con solo fratelli in coda la valvola ha registrato {logged_with_only_siblings} errori: ha passato il "
            "turno a un fratello, o registra a ogni controllo")
        assert passed, f"la pagina di un'altra richiesta non è entrata entro {_VALVE_S} s dal suo arrivo"
        assert logged_after == 1, f"un passaggio della valvola registrato {logged_after} volte"

    def test_the_bodies_of_one_request_are_never_analysed_together_even_after_the_safety_valve(
            self, site, http_client, monkeypatch):
        """Un corpo di una `/http` da quattro resta bloccato e la valvola passa il turno: comunque vada poi il turno,
        anche a un fratello del corpo bloccato, nessun fratello entra nell'analisi finché lui non finisce, e i corpi
        della richiesta non si sovrappongono mai."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held=set(_FOUR_BODIES))
        waits = _TurnWaits(monkeypatch)
        requests = []
        try:
            four, stuck, siblings = _stuck_request(http_client, site, gate, waits)
            requests.append(four)
            other = _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB)})
            requests += other
            clock.advance(61)
            other[0].wait(_VALVE_S)    # l'altra richiesta finisce, e il turno torna in coda: ai fratelli
            alongside = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert not alongside, "un fratello del corpo bloccato è entrato nell'analisi mentre lui era ancora dentro"
        assert all(r.analysed(pages=4 if r is requests[0] else 1) for r in requests), [r.describe() for r in requests]
        overlaps = _overlapping(gate.spans, _FOUR_BODIES)
        assert not overlaps, f"corpi della stessa richiesta analizzati insieme: {overlaps}"

    def test_after_the_safety_valve_the_turn_does_not_go_back_to_a_sibling_of_the_stuck_body(
            self, site, http_client, monkeypatch):
        """Un corpo di una `/http` da quattro resta bloccato e la valvola passa il turno alla pagina di un'altra
        richiesta. Finita quella, il turno non va a un fratello del corpo ancora in analisi, che lo terrebbe aspettando
        la fine del fratello: va alla pagina di una terza richiesta, più lunga dei fratelli, che entra senza aspettare
        un'altra valvola. L'orologio del turno non si muove più."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held=set(_FOUR_BODIES))
        waits = _TurnWaits(monkeypatch)
        requests = []
        try:
            four, stuck, siblings = _stuck_request(http_client, site, gate, waits)
            requests.append(four)
            requests += _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB),
                                                          "corpo-terzo": _sized_page("corpo-terzo", 16 * _KIB)})
            clock.advance(61)
            other_done = requests[1].wait(_VALVE_S)
            third = _first_of(gate.entered("corpo-terzo"), timeout=_VALVE_S)
            alongside = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert other_done, f"la pagina dell'altra richiesta non ha avuto il turno dalla valvola entro {_VALVE_S} s"
        assert third, (f"finita l'altra richiesta, la terza non è entrata entro {_VALVE_S} s: il turno è andato a un "
                       "fratello del corpo ancora in analisi")
        assert not alongside, "un fratello del corpo bloccato è entrato nell'analisi accanto a lui"
        assert all(r.analysed(pages=4 if r is requests[0] else 1) for r in requests), [r.describe() for r in requests]
        assert not _overlapping(gate.spans, _FOUR_BODIES), _overlapping(gate.spans, _FOUR_BODIES)

    def test_when_the_stuck_body_ends_with_only_its_siblings_waiting_one_of_them_enters_at_once(
            self, site, http_client, monkeypatch):
        """Un corpo di una `/http` da quattro resta bloccato; la valvola passa il turno alla pagina di un'altra
        richiesta, che finisce, e in coda restano solo i fratelli del corpo bloccato, che non entrano accanto a lui.
        Quando il corpo bloccato finisce, senza turno da passare, il primo fratello designato entra subito: non aspetta
        un controllo della valvola, da qui uno ogni 60 s veri."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held=set(_FOUR_BODIES))
        waits = _TurnWaits(monkeypatch)
        requests = []
        try:
            four, stuck, siblings = _stuck_request(http_client, site, gate, waits)
            requests.append(four)
            requests += _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB)})
            clock.advance(61)
            other_done = requests[1].wait(_VALVE_S)
            monkeypatch.setattr(http_fingerprint, _POLL, 60.0, raising=False)
            alongside = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ALONGSIDE_S)
            gate.release(stuck)
            first = _first_of(*(gate.entered(marker) for marker in siblings), timeout=_ENTRY_S)
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert other_done, f"la pagina dell'altra richiesta non ha avuto il turno dalla valvola entro {_VALVE_S} s"
        assert not alongside, "un fratello del corpo bloccato è entrato nell'analisi accanto a lui"
        assert first, (f"finito il corpo bloccato, nessun fratello è entrato entro {_ENTRY_S} s: il turno libero non è "
                       "stato consegnato a chi aspettava")
        assert all(r.analysed(pages=4 if r is requests[0] else 1) for r in requests), [r.describe() for r in requests]
        assert not _overlapping(gate.spans, _FOUR_BODIES), _overlapping(gate.spans, _FOUR_BODIES)

    def test_a_body_arriving_while_its_sibling_is_still_in_analysis_does_not_take_the_free_turn(
            self, site, http_client, monkeypatch):
        """Una `/http` da due corpi: il primo resta bloccato, il secondo si scarica in ritardo. La valvola passa il
        turno alla pagina di un'altra richiesta, che finisce, e il turno resta libero. Il secondo corpo arriva e non lo
        prende, perché il fratello è ancora in analisi: la pagina di una terza richiesta, arrivata dopo, entra subito.
        Finito il corpo bloccato, entra il secondo."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-coppia0"})
        waits = _TurnWaits(monkeypatch)
        late_url, downloaded = "https://corpo-coppia.example", threading.Event()

        def fetch(url, **kwargs):
            if url == late_url:
                _quiet_wait(downloaded, _HOLD_LIMIT_S)
            return site.fetch(url, **kwargs)

        monkeypatch.setattr(http_fingerprint, "http_get_with_retry", fetch)
        site.pages.update({"http://corpo-coppia.example": _readable_page("corpo-coppia0"),
                           late_url: _readable_page("corpo-coppia1")})
        requests = [_Request(http_client, "corpo-coppia.example")]
        try:
            assert gate.entered("corpo-coppia0").wait(10), "il primo corpo non è entrato nell'analisi"
            requests += _queue(http_client, site, waits, {"corpo-estraneo": _sized_page("corpo-estraneo", 8 * _KIB)})
            clock.advance(61)
            other_done = requests[1].wait(_VALVE_S)
            downloaded.set()
            arrived = _first_of(waits.started("corpo-coppia1"), gate.entered("corpo-coppia1"), timeout=10)
            alongside = _first_of(gate.entered("corpo-coppia1"), timeout=_ALONGSIDE_S)
            _serve_pages(site, "corpo-terzo")
            requests.append(_Request(http_client, "corpo-terzo.example"))
            third = _first_of(gate.entered("corpo-terzo"), timeout=_ENTRY_S)
            gate.release("corpo-coppia0")
            second = _first_of(gate.entered("corpo-coppia1"), timeout=_ENTRY_S)
        finally:
            downloaded.set()
            gate.release()
        for request in requests:
            request.wait(30)

        assert other_done, f"la pagina dell'altra richiesta non ha avuto il turno dalla valvola entro {_VALVE_S} s"
        assert not alongside, "il secondo corpo è entrato nell'analisi accanto al fratello bloccato"
        assert third, (f"col turno libero la pagina di una terza richiesta non è entrata entro {_ENTRY_S} s: il "
                       "secondo corpo ha preso il turno mentre il fratello era in analisi")
        assert arrived, "il secondo corpo non si è messo in coda per il turno"
        assert second, f"finito il corpo bloccato, il secondo corpo non è entrato entro {_ENTRY_S} s"
        assert all(r.analysed(pages=2 if r is requests[0] else 1) for r in requests), [r.describe() for r in requests]

    def test_a_turn_handed_over_while_the_wait_runs_out_is_not_taken_for_a_stuck_one(
            self, site, http_client, monkeypatch, caplog):
        """La consegna del turno arriva mentre l'attesa di controllo della pagina scade, e la pagina riprende in
        ritardo, oltre `ANALYSIS_STUCK_S` sull'orologio del turno, con una pagina di un'altra richiesta in coda. Il
        turno è suo: non lo prende per un turno bloccato e non lo passa, quindi la pagina in coda aspetta invece di
        entrare accanto a lei. Nessun errore. Mentre la pagina riprende, l'attesa di quella in coda è ferma anche lei:
        il controllo della valvola lo fa solo la pagina che riprende."""
        monkeypatch.setattr(http_fingerprint, _STUCK, 60.0, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held={"corpo-lento", "corpo-tarda"})
        waits = _TurnWaits(monkeypatch, late={"corpo-tarda", "corpo-dopo"})
        caplog.set_level(logging.ERROR, logger=http_fingerprint.logger.name)
        _serve_pages(site, "corpo-lento", "corpo-tarda", "corpo-dopo")
        slow = _Request(http_client, "corpo-lento.example")
        requests = [slow]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests.append(_Request(http_client, "corpo-tarda.example"))
            assert waits.paused("corpo-tarda").wait(10), _NOT_PAUSED
            gate.release("corpo-lento")
            assert slow.wait(30), "l'analisi trattenuta non è finita"   # il turno è consegnato a chi riprende tardi
            requests.append(_Request(http_client, "corpo-dopo.example"))
            assert waits.paused("corpo-dopo").wait(10), _NOT_PAUSED
            clock.advance(61)
            waits.resume("corpo-tarda")
            assert gate.entered("corpo-tarda").wait(10), "la pagina che ha ricevuto il turno non è entrata"
            monkeypatch.setattr(http_fingerprint, _STUCK, 1e9, raising=False)   # da qui nessun turno è bloccato
            waits.resume("corpo-dopo")
            alongside = _first_of(gate.entered("corpo-dopo"), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
            waits.resume()
        for request in requests:
            request.wait(30)

        assert not alongside, ("la pagina in coda è entrata accanto a quella che riprendeva in ritardo: il turno "
                               "consegnato è stato preso per un turno bloccato e passato")
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]
        assert not _turn_errors(caplog), f"errori registrati: {[r.getMessage() for r in _turn_errors(caplog)]}"

    def test_a_page_arriving_while_the_turn_is_handed_over_waits_for_it(self, site, http_client, monkeypatch):
        """Il titolare consegna il turno a chi aspettava, che resta in analisi; una terza pagina arriva in quel
        momento e aspetta, invece di entrare nell'analisi insieme a lui: mai due corpi analizzati insieme."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, 30.0, raising=False)
        gate = _AnalysisGate(monkeypatch, held={"corpo-primo", "corpo-secondo"})
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-primo", "corpo-secondo", "corpo-terzo")
        first = _Request(http_client, "corpo-primo.example")
        requests = [first]
        try:
            assert gate.entered("corpo-primo").wait(10), "l'analisi trattenuta non è cominciata"
            requests.append(_Request(http_client, "corpo-secondo.example"))
            assert waits.started("corpo-secondo").wait(10), "la seconda pagina non si è messa in attesa del turno"
            gate.release("corpo-primo")
            first.wait(30)
            assert gate.entered("corpo-secondo").wait(10), "il turno non è passato alla seconda pagina"
            requests.append(_Request(http_client, "corpo-terzo.example"))
            arrived = _first_of(waits.started("corpo-terzo"), gate.entered("corpo-terzo"), timeout=10)
            third_entered = gate.entered("corpo-terzo").is_set()
        finally:
            gate.release()
        for request in requests:
            request.wait(30)

        assert arrived, "la terza pagina non ha né atteso il turno né cominciato l'analisi"
        assert not third_entered, "la terza pagina è entrata nell'analisi mentre la seconda aveva il turno"
        assert gate.most_together == 1, f"{gate.most_together} corpi analizzati insieme"
        assert all(r.analysed() for r in requests), [r.describe() for r in requests]

    def test_the_bodies_of_one_request_wait_for_the_turn_together(self, site, http_client, monkeypatch):
        """Un'analisi di un'altra richiesta resta in corso. Una pagina servita su tutti e quattro gli URL mette in coda
        per il turno i suoi quattro corpi insieme, non uno dopo l'altro: ognuno concorre per la sua lunghezza con le
        pagine delle altre richieste."""
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        bodies = _serve_four_bodies(site)
        slow = _Request(http_client, "corpo-lento.example")
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            four = _Request(http_client, "corpo-quattro.example", check_www=True)
            waiting = [marker for marker in bodies if waits.started(marker).wait(10)]
        finally:
            gate.release()
        slow.wait(30)
        four.wait(30)

        assert waiting == bodies, f"in coda per il turno durante l'analisi in corso: {waiting} su {bodies}"
        assert four.analysed(pages=4), four.describe()

    def test_the_bodies_of_one_request_enter_one_at_a_time_after_the_analysis_in_progress(
            self, site, http_client, monkeypatch):
        """Un'analisi di un'altra richiesta resta in corso: nessuno dei quattro corpi di una `/http` entra accanto a
        lei, nemmeno con un'attesa massima `ANALYSIS_MAX_WAIT_S` di un centesimo di secondo e l'orologio del turno
        avanti di 59 s, sotto la valvola di sicurezza; finita, i quattro entrano uno alla volta."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _AGING, 0.01, raising=False)
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        clock = _TurnClock(monkeypatch)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento", pause_s=0.005)
        waits = _TurnWaits(monkeypatch)
        _serve_pages(site, "corpo-lento")
        bodies = _serve_four_bodies(site)
        slow = _Request(http_client, "corpo-lento.example")
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            four = _Request(http_client, "corpo-quattro.example", check_www=True)
            assert _first_of(*(waits.started(marker) for marker in bodies), timeout=10), (
                "nessun corpo si è messo in attesa del turno")
            clock.advance(59)
            alongside = _first_of(*(gate.entered(marker) for marker in bodies), timeout=_ALONGSIDE_S)
        finally:
            gate.release()
        slow.wait(30)
        four.wait(30)

        assert four.analysed(pages=4), four.describe()
        siblings = _overlapping(gate.spans, bodies)
        assert not siblings, f"corpi della stessa richiesta analizzati insieme: {siblings}"
        assert not alongside, "un corpo è entrato nell'analisi accanto a quella in corso"
        overlaps = _overlapping(gate.spans)
        assert not overlaps, f"corpi analizzati insieme: {overlaps}"

    def test_an_analysis_that_fails_leaves_the_turn_free(self, site, http_client, monkeypatch):
        """L'analisi di un corpo solleva: la pagina che arriva dopo, senza altre analisi in corso, non aspetta."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, _LONG_WAIT_S, raising=False)
        gate = _AnalysisGate(monkeypatch, failing={"corpo-errore"})
        _serve_pages(site, "corpo-errore")
        failed = _Request(http_client, "corpo-errore.example")
        failed.wait(30)

        assert gate.entered("corpo-errore").is_set(), "l'analisi destinata a fallire non è cominciata"
        _assert_no_wait_without_contention(http_client, site, gate, "corpo-dopo")

    @pytest.mark.parametrize("when", ["before_handover", "at_handover"])
    def test_a_wait_that_raises_does_not_lose_the_turn(self, site, http_client, monkeypatch, when):
        """L'attesa del turno di una pagina solleva, prima che il turno le arrivi o nel momento in cui arriva: la
        pagina fallisce, ma il turno non resta a lei né in coda. La pagina in attesa davanti a lei tiene il suo
        posto ed entra dopo l'analisi in corso, mai insieme; poi la pagina successiva, senza altre analisi in
        corso, non aspetta."""
        monkeypatch.setattr(http_fingerprint, _MAX_WAIT, _LONG_WAIT_S, raising=False)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento", pause_s=0.005)
        failing = {"before_handover": {"fail_before": {"corpo-rotta"}}, "at_handover": {"fail_after": {"corpo-rotta"}}}
        waits = _TurnWaits(monkeypatch, **failing[when])
        _serve_pages(site, "corpo-lento", "corpo-prima", "corpo-rotta")
        slow = _Request(http_client, "corpo-lento.example")
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            ahead = _Request(http_client, "corpo-prima.example")
            assert waits.started("corpo-prima").wait(10), "la pagina davanti non si è messa in attesa del turno"
            broken = _Request(http_client, "corpo-rotta.example")
            assert waits.started("corpo-rotta").wait(10), "la pagina non si è messa in attesa del turno"
            if when == "before_handover":
                broken.wait(30)
        finally:
            gate.release()
        for request in (slow, ahead, broken):
            request.wait(30)

        assert slow.analysed(), slow.describe()
        assert ahead.analysed(), ahead.describe()
        overlaps = _overlapping(gate.spans)
        assert not overlaps, f"corpi analizzati insieme: {overlaps}"
        _assert_no_wait_without_contention(http_client, site, gate, "corpo-dopo")

    def test_a_wait_that_raises_when_the_turn_arrives_lets_the_sibling_in(self, site, http_client, monkeypatch):
        """Una `/http` da due corpi aspetta il turno dietro un'analisi in corso. Il turno arriva al primo corpo, il più
        corto, e la sua attesa solleva proprio in quel momento: il corpo fallisce senza analisi, e la richiesta non
        resta fra quelle con un corpo in analisi. Il fratello entra subito dopo, e poi il turno è libero."""
        _TurnClock(monkeypatch)     # fermo: nessun corpo invecchia, entra prima il più corto
        monkeypatch.setattr(http_fingerprint, _POLL, 0.01, raising=False)
        gate = _AnalysisGate(monkeypatch, held="corpo-lento")
        waits = _TurnWaits(monkeypatch, fail_after={"corpo-coppia0"})
        _serve_pages(site, "corpo-lento")
        site.pages.update({"http://corpo-coppia.example": _sized_page("corpo-coppia0", 4 * _KIB),
                           "https://corpo-coppia.example": _sized_page("corpo-coppia1", 8 * _KIB)})
        requests = [_Request(http_client, "corpo-lento.example")]
        try:
            assert gate.holding.wait(10), "l'analisi trattenuta non è cominciata"
            requests.append(_Request(http_client, "corpo-coppia.example"))
            for marker in ("corpo-coppia0", "corpo-coppia1"):
                assert waits.started(marker).wait(10), f"{marker} non si è messo in attesa del turno"
            gate.release("corpo-lento")
            sibling = _first_of(gate.entered("corpo-coppia1"), timeout=_ENTRY_S)
        finally:
            gate.release()
            waits.fail("corpo-coppia1")    # un fratello rimasto in coda fallisce, così la sua richiesta finisce
        for request in requests:
            request.wait(30)

        assert requests[0].analysed(), requests[0].describe()
        assert not gate.entered("corpo-coppia0").is_set(), "il corpo la cui attesa è fallita è entrato nell'analisi"
        assert sibling, (f"dopo l'attesa fallita del primo corpo il fratello non è entrato entro {_ENTRY_S} s: la "
                         "richiesta è rimasta fra quelle con un corpo in analisi")
        _assert_no_wait_without_contention(http_client, site, gate, "corpo-dopo")
