"""PERF-05 — `GET /reputation` ha una scadenza per richiesta e un'attesa limitata del posto VT.

L'orchestrator attende `/reputation` al più 45 s, poi registra `None` e passa oltre. Una richiesta servita oltre quel
limite consumerebbe comunque un posto della quota VT e le chiamate OTX/ST, con il risultato perso; a valle la sezione
intera sarebbe un modulo fallito, riportata dal ciclo precedente, e il dominio finirebbe fra i dati insufficienti nel
canale dei casi. Due attese possono allungare una richiesta: il posto della quota VT, che si libera solo quando la
chiamata più lontana esce dalla finestra di `VT_RATE_WINDOW` (60 s), con gli altri richiedenti in coda al lucchetto
della quota; e le tre GET, ognuna fino al proprio `timeout=` o anche oltre (risoluzione del nome, risposta a goccia).

Interfaccia che questi test fissano (`services.reputation`, attributi del modulo letti a ogni richiesta):

* `REPUTATION_DEADLINE_S = 40` — scadenza di una richiesta `/reputation`, misurata da quando la richiesta inizia;
* `VT_MAX_WAIT_S = 35` — attesa massima di un posto della quota VT, lucchetto compreso; oltre, VT è saltato;
* `REPUTATION_HTTP_TIMEOUT_S = 15` — `timeout=` massimo di una GET verso VT, OTX o SecurityTrails;
* `VT_MAX_WAIT_S < REPUTATION_DEADLINE_S < services.orchestrator.TIMEOUT` (45 di default);
* `VT_RATE_LIMIT`, `VT_RATE_WINDOW`, `_vt_call_times` (lista globale degli istanti `time.time()` delle chiamate VT
  reali, in ordine crescente), `_vt_wait_for_slot()` senza argomenti (un ritorno normale concede il posto: i test la
  sostituiscono con `lambda: None`), le chiavi `VT_API_KEY`, `OTX_API_KEY`, `ST_API_KEY` e le GET fatte come
  `requests.get(url, headers=..., timeout=...)` attraverso il nome `requests` del modulo, che qui è un oggetto con il
  solo `get`;
* il gestore chiama `_check_vt(domain)`, `_check_otx(domain)` e `_check_st(domain)` attraverso i nomi del modulo a
  ogni richiesta, e l'attesa del posto VT dorme con `time.sleep` attraverso il nome `time` del modulo: per simulare
  uno scheduler in ritardo alcuni test avvolgono quelle funzioni (la fonte parte tardi) o allungano quel sonno.

Comportamento atteso:

1. l'attesa di un posto VT, lucchetto compreso, non supera `VT_MAX_WAIT_S` né la scadenza; oltre, VT è saltato:
   dict completo con i numeri a zero ed `error` stringa non vuota diversa da `VT_NOT_FOUND_ERROR`, nessuna GET a VT,
   nessun posto in `_vt_call_times`, né durante la richiesta né dopo: un posto non preso entro il limite non si
   prende più, anche quando lo scheduler sveglia o avvia in ritardo il thread che lo attende;
   senza un posto entro il limite si attende fino al limite, mai meno, anche quando si può prevedere che il posto
   arriverà oltre: rinunciando in anticipo le richieste in fila correrebbero a quota esaurita e perderebbero VT;
2. `/reputation` risponde entro `REPUTATION_DEADLINE_S` più un margine, anche quando una GET non rispetta il
   proprio `timeout=` (risoluzione del nome lenta, risposta a goccia);
3. una fonte richiesta e non raggiunta entro la scadenza è un dict completo con i numeri a zero ed `error`
   stringa non vuota, mai `None` (`None` significa «fonte non richiesta o senza chiave», COL-16);
4. OTX e SecurityTrails non aspettano il posto di VT: lenti ma entro il loro timeout, sono osservati anche
   mentre VT attende fino al limite;
5. il `timeout=` di ogni GET non supera `REPUTATION_HTTP_TIMEOUT_S` né il tempo che resta alla richiesta
   (nessun minimo che lo porti oltre la scadenza), e nessuna GET parte dopo la scadenza, nemmeno da una fonte
   avviata in ritardo;
6. la quota VT non è mai superata, con richiedenti concorrenti e posti già occupati;
7. con attese sotto il limite la sezione è completa e ogni fonte osservata, con una GET per fonte (URL e header dei
   fornitori) e la GET a VT solo a posto libero;
8. le guardie di configurazione di PERF-01 (`VT_RATE_LIMIT` o `VT_RATE_WINDOW` non positivi: `ValueError` che nomina
   la variabile) scattano subito, anche a quota esaurita;
9. i thread che il gestore avvia finiscono quando finiscono le loro GET: nessun thread resta vivo dopo (ogni
   prova che passa dal gestore lo controlla, così un thread rimasto si vede qualunque sia l'ordine dei test);
10. a valle, un VT saltato è una fonte non osservata: il modulo non è fallito, VT si riporta dal ciclo
    precedente (COL-16) e non esce alcun alert.

Tempi: tempo reale in scala, costanti impostate con `monkeypatch.setattr(..., raising=False)` come nei test di
SEC-29. Finestra 1,5 s, attesa massima 0,7 s, scadenza 1,0 s (2,0 s nei test con GET sorde), timeout per GET 0,8 s
(in produzione 60, 35, 40, 15: il timeout per GET qui è più vicino alla scadenza perché una GET che parte tardi con il
timeout intero si veda). Una risposta del gestore arriva entro la scadenza più `_LATE_ANSWER` = 10 % della scadenza,
meno del 12,5 % che separa i 40 s della scadenza dai 45 s dell'orchestrator. Con le GET sorde la risposta cade proprio
alla scadenza, con un ritardo fisso di qualche centesimo di secondo sotto carico: lì la scadenza è di 2,0 s perché il
10 % superi di molto quel ritardo. Margine sulle attese del posto VT `_TOL_S` = 0,35 s; su istante + `timeout=` di una
GET `_TIMEOUT_TOL_S` = 0,15 s (lì conta solo lo scarto fra l'inizio misurato dal test e quello del gestore). Gli
errori che questi test separano stanno almeno 0,45 s oltre il limite sulle attese, 0,25 s su istante + `timeout`.
Sul lato basso un VT saltato non arriva sotto `_FLOOR_S` = 0,85 × attesa massima: sonno e lucchetto non finiscono in
anticipo, quindi il carico allunga l'attesa piena e non la accorcia. Oltre scadenza + `_GIVE_UP_S`
il test smette di aspettare: libera la rete finta (ogni GET in corso finisce con un errore di connessione), la
richiesta finisce da sola e la sua durata entra comunque nei test sui tempi.

Rete: nessuna. La rete finta registra fonte, dominio, istante e `timeout` di ogni GET; una fonte «ubbidiente»
risponde dopo la sua latenza se il `timeout` ricevuto basta, altrimenti dopo il `timeout` solleva il vero
`requests.exceptions.ReadTimeout`; una fonte «sorda» risponde solo dopo la sua latenza, qualunque `timeout`
riceva. Un `timeout` a coppia conta come somma, `None` come illimitato.
"""
import copy
import math
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import requests
from fastapi.testclient import TestClient

import services.reputation as reputation
from shared.constants import VT_NOT_FOUND_ERROR
from shared.utils import collection_failed, reputation_source_unobserved

_LIMIT = 4                 # VT_RATE_LIMIT
_WINDOW_S = 1.5            # VT_RATE_WINDOW (60 s in produzione)
_MAX_WAIT_S = 0.7          # VT_MAX_WAIT_S (35 s)
_DEADLINE_S = 1.0          # REPUTATION_DEADLINE_S (40 s)
_DEAF_DEADLINE_S = 2.0     # la scadenza nei test con GET sorde, dove la risposta cade alla scadenza
_HTTP_TIMEOUT_S = 0.8      # REPUTATION_HTTP_TIMEOUT_S (15 s)
_LATE_ANSWER = 0.10        # una risposta arriva entro la scadenza × (1 + questo)
_TOL_S = 0.35              # margine sulle attese del posto VT
_TIMEOUT_TOL_S = 0.15      # margine su istante + `timeout` di una GET
_FLOOR_S = 0.85 * _MAX_WAIT_S   # nessun VT saltato sotto questa attesa (lato basso dell'attesa piena)
_GIVE_UP_S = 1.5           # oltre scadenza + questo la richiesta non ha risposto
# OTX e ST «lenti»: oltre il tempo che resta dopo un'attesa VT piena (1,0 - 0,7 = 0,3 s), entro il timeout per GET
# (0,8 s), e due in fila stanno nella scadenza con 0,24 s di margine.
_SLOW_S = 0.38
_DEAF_S = 5.0              # una GET sorda: dura più di ogni limite, il test la libera
_FAKE_CAP_S = 20.0         # nessuna attesa della rete finta dura di più
_JOIN_S = 30.0
_THREAD_GRACE_S = 2.0

_KEYS = {"VT_API_KEY": "vt-test-key", "OTX_API_KEY": "otx-test-key", "ST_API_KEY": "st-test-key"}
_HOSTS = {"www.virustotal.com": "vt", "otx.alienvault.com": "otx", "api.securitytrails.com": "st"}

_VT_ZERO = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0, "reputation": 0, "categories": {}}
_OTX_ZERO = {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": []}
_ST_ZERO = {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None}
_ZERO = {"virustotal": _VT_ZERO, "otx": _OTX_ZERO, "securitytrails": _ST_ZERO}


# ── Risposte dei fornitori ──────────────────────────────────────────────────────────────────────────────────

class _Reply:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return copy.deepcopy(self._payload)


def _vt_reply(malicious=3):
    return _Reply(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 10},
        "reputation": -10 if malicious else 0, "categories": {"vendor": "phishing"}}}})


def _otx_reply(pulses=2):
    return _Reply(200, {"pulse_info": {"count": pulses, "pulses": [
        {"name": f"pulse-{i}", "tags": ["tag-a"], "malware_families": []} for i in range(pulses)]}})


_ST_BODY = {"subdomain_count": 4, "current_dns": {"a": {"values": [{"ip": "192.0.2.10"}]}}, "alexa_rank": 1234}


def _observed_vt(malicious=3):
    return {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 10,
            "reputation": -10 if malicious else 0, "categories": {"vendor": "phishing"}, "error": None}


def _observed_otx(pulses=2):
    return {"pulse_count": pulses, "pulse_titles": [f"pulse-{i}" for i in range(pulses)],
            "tags": ["tag-a"] if pulses else [], "malware_families": [], "error": None}


_OBSERVED_ST = {**_ST_BODY, "error": None}


def _obey(reply, latency=0.0):
    """Risponde dopo `latency` se il `timeout` ricevuto basta, altrimenti `ReadTimeout` allo scadere del timeout."""
    return ("obey", latency, reply)


def _silent():
    return ("obey", math.inf, None)


def _deaf(reply, latency=_DEAF_S):
    """Risponde dopo `latency` qualunque `timeout` riceva: un nome che si risolve piano, una risposta a goccia."""
    return ("deaf", latency, reply)


def _plan(vt=None, otx=None, st=None):
    return {"vt": vt or _obey(_vt_reply()), "otx": otx or _obey(_otx_reply()), "st": st or _obey(_Reply(200, _ST_BODY))}


# ── La rete finta ───────────────────────────────────────────────────────────────────────────────────────────

def _seconds(timeout):
    if timeout is None:
        return math.inf
    if isinstance(timeout, (tuple, list)):
        return sum(math.inf if part is None else float(part) for part in timeout)
    return float(timeout)


class _Net:
    """Sostituisce il modulo `requests` di `services.reputation`: il solo `get`."""

    def __init__(self, plan):
        self.plan = plan
        self.calls = []
        self._lock = threading.Lock()
        self._released = threading.Event()

    def release(self):
        self._released.set()

    def _pause(self, seconds):
        if seconds <= 0:
            stop = self._released.is_set()
        else:
            stop = self._released.wait(min(seconds, _FAKE_CAP_S))
        if stop:
            raise requests.exceptions.ConnectionError("connection closed by the test")

    def get(self, url, **kwargs):
        host = url.split("/")[2] if url.count("/") >= 2 else ""
        source = _HOSTS.get(host)
        if source is None:
            raise AssertionError(f"GET non atteso: {url}")
        domain = next((part for part in url.split("/") if part.endswith(".example")), None)
        call = SimpleNamespace(source=source, domain=domain, url=url, headers=dict(kwargs.get("headers") or {}),
                               timeout=_seconds(kwargs.get("timeout")), t=time.monotonic(), wall=time.time())
        with self._lock:
            self.calls.append(call)
        mode, latency, reply = self.plan[source]
        if mode == "obey" and latency > call.timeout:
            self._pause(call.timeout)
            raise requests.exceptions.ReadTimeout(f"Read timed out. (read timeout={kwargs.get('timeout')})")
        self._pause(latency)
        return reply


# ── Una prova: richieste concorrenti con la rete finta ──────────────────────────────────────────────────────

def _ask(target, domain, sources, box):
    box["start"] = time.monotonic()
    try:
        if target == "handler":
            response = TestClient(reputation.app).get("/reputation", params={"domain": domain, "sources": sources})
            box["status"] = response.status_code
            box["body"] = response.json()
        else:
            box["body"] = reputation._check_vt(domain)
    except BaseException as exc:      # riportata dal test
        box["error"] = repr(exc)
    finally:
        box["end"] = time.monotonic()


def _ask_in_turn(target, domains, sources, boxes):
    for domain, box in zip(domains, boxes, strict=True):
        _ask(target, domain, sources, box)


def _run(target, count, *, plan=None, busy=(), window=_WINDOW_S, limit=_LIMIT, hold_s=None, stub_wait=False,
         sources="vt,otx,st", prefix="acme-typo", serial=False, deadline=_DEADLINE_S, patch=None):
    """`count` richieste insieme, o una dopo l'altra con `serial` (`target` "handler": `GET /reputation`;
    "check_vt": `_check_vt` da solo).

    `busy`: un posto VT occupato per ogni valore, che si libera quel numero di secondi dopo la partenza (la quota
    è esaurita se i valori sono `limit`). `hold_s`: con tutte le risposte arrivate, si aspetta fino a quell'istante
    dalla partenza, poi si libera la rete e si contano GET e posti. `patch`: chiamata con il `MonkeyPatch` della
    prova dopo le impostazioni comuni. Ritorna le risposte, le GET, i posti VT all'inizio e alla fine e i thread
    nati durante la prova ancora vivi dopo la liberazione."""
    net = _Net(plan or _plan())
    domains = [f"{prefix}-{i}.example" for i in range(count)]
    per_request = (deadline if target == "handler" else _MAX_WAIT_S) + _GIVE_UP_S
    run = SimpleNamespace(domains=domains, deadline=deadline, bound=per_request * (count if serial else 1))
    with pytest.MonkeyPatch.context() as mp:
        for name, value in _KEYS.items():
            mp.setattr(reputation, name, value)
        mp.setattr(reputation, "requests", net)
        mp.setattr(reputation, "VT_RATE_LIMIT", limit)
        mp.setattr(reputation, "VT_RATE_WINDOW", window)
        mp.setattr(reputation, "REPUTATION_DEADLINE_S", deadline, raising=False)
        mp.setattr(reputation, "VT_MAX_WAIT_S", _MAX_WAIT_S, raising=False)
        mp.setattr(reputation, "REPUTATION_HTTP_TIMEOUT_S", _HTTP_TIMEOUT_S, raising=False)
        if stub_wait:
            mp.setattr(reputation, "_vt_wait_for_slot", lambda: None)
        if patch is not None:
            patch(mp)
        now = run.wall0 = time.time()
        run.slots_before = sorted(now - (window - free) for free in busy)
        mp.setattr(reputation, "_vt_call_times", list(run.slots_before))
        before = set(threading.enumerate())
        boxes = [{} for _ in domains]
        if serial:
            askers = [threading.Thread(target=_ask_in_turn, args=(target, domains, sources, boxes),
                                       name="perf05-ask-in-turn", daemon=True)]
        else:
            askers = [threading.Thread(target=_ask, args=(target, d, sources, b), name=f"perf05-ask-{i}", daemon=True)
                      for i, (d, b) in enumerate(zip(domains, boxes, strict=True))]
        run.t0 = time.monotonic()
        for th in askers:
            th.start()
        for th in askers:
            th.join(max(0.0, run.t0 + run.bound - time.monotonic()))
        run.in_time = [not th.is_alive() for th in askers] * (count if serial else 1)
        if hold_s is not None and all(run.in_time):
            time.sleep(max(0.0, run.t0 + hold_s - time.monotonic()))
        net.release()
        for th in askers:
            th.join(_JOIN_S)
        run.stuck = [th.name for th in askers if th.is_alive()]
        end = time.monotonic() + _THREAD_GRACE_S
        while True:
            born = [th for th in threading.enumerate() if th not in before and th not in askers and th.is_alive()]
            if not born or time.monotonic() >= end:
                break
            time.sleep(0.02)
        run.threads_left = sorted(th.name for th in born)
        run.slots_after = list(reputation._vt_call_times)
    run.calls = sorted(net.calls, key=lambda c: c.t)
    run.answers = []
    for domain, box, in_time in zip(domains, boxes, run.in_time, strict=True):
        run.answers.append(SimpleNamespace(
            domain=domain, start=box.get("start"), elapsed=box["end"] - box["start"] if "end" in box else None,
            in_time=in_time, status=box.get("status"), body=box.get("body"), error=box.get("error")))
    return run


def _bodies(run):
    """I corpi delle risposte, anche di quelle arrivate oltre il limite della prova (la puntualità è dei test sui
    tempi): ogni richiesta è finita, senza eccezioni e, per `/reputation`, con 200."""
    assert not run.stuck, f"richieste ancora in corso dopo la liberazione della rete: {run.stuck}"
    errors = [(a.domain, a.error) for a in run.answers if a.error]
    assert not errors, errors
    wrong = [(a.domain, a.status) for a in run.answers if a.status not in (None, 200)]
    assert not wrong, wrong
    return [a.body for a in run.answers]


def _assert_answered_within(run, limit, what="risposte"):
    durations = sorted(math.inf if a.elapsed is None else round(a.elapsed, 2) for a in run.answers)
    assert durations[-1] <= limit, f"{what} in {durations} s, limite {limit:.2f} s"


def _assert_answered_by_the_deadline(run):
    limit = run.deadline * (1 + _LATE_ANSWER)
    durations = sorted(math.inf if a.elapsed is None else a.elapsed for a in run.answers)
    assert durations[-1] <= limit, (f"risposte in {[round(d, 3) for d in durations]} s, scadenza {run.deadline} s, "
                                    f"limite {limit:.2f} s")


def _assert_waited_up_to_the_max_wait(run, what):
    durations = sorted(math.inf if a.elapsed is None else a.elapsed for a in run.answers)
    assert durations[0] >= _FLOOR_S, (f"{what} con VT saltato in {[round(d, 3) for d in durations]} s: rinuncia "
                                      f"sotto {_FLOOR_S:.3f} s, attesa massima {_MAX_WAIT_S} s")


def _gets(run, source):
    return [c for c in run.calls if c.source == source]


def _new_slots(run):
    return [t for t in run.slots_after if t not in run.slots_before]


def _assert_complete_with_error(section, key):
    value = section[key]
    assert isinstance(value, dict), f"{key}: fonte richiesta lasciata {value!r} invece di un dict con `error`"
    assert isinstance(value.get("error"), str) and value["error"], f"{key}: `error` {value.get('error')!r}"
    assert {k: v for k, v in value.items() if k != "error"} == _ZERO[key], f"{key}: {value}"
    assert reputation_source_unobserved(value), f"{key}: {value}"


def _assert_vt_skipped(section):
    _assert_complete_with_error(section, "virustotal")
    assert section["virustotal"]["error"] != VT_NOT_FOUND_ERROR, "un VT saltato non è il 404 di VT (un'osservazione)"


def _assert_gets_fit_in_the_time_left(run):
    starts = {a.domain: a.start for a in run.answers}
    over = []
    for c in run.calls:
        offset = c.t - starts[c.domain]
        if (c.timeout > _HTTP_TIMEOUT_S + 1e-9 or offset > run.deadline
                or offset + c.timeout > run.deadline + _TIMEOUT_TOL_S):
            over.append((c.source, round(offset, 3), c.timeout))
    assert run.calls, "nessuna GET"
    assert not over, (f"GET (fonte, partenza dall'inizio della richiesta, timeout) oltre il timeout per GET "
                      f"{_HTTP_TIMEOUT_S} s o oltre la scadenza {run.deadline} s: {over}")


def _assert_no_thread_left(run):
    assert not run.stuck, f"richieste ancora in corso dopo la liberazione della rete: {run.stuck}"
    assert not run.threads_left, f"thread ancora vivi a GET finite: {run.threads_left}"


# ── 0. Le costanti ─────────────────────────────────────────────────────────────────────────────────────────

class TestConstants:

    def test_deadline_wait_and_get_timeout_have_the_decided_values(self):
        values = {name: getattr(reputation, name, None)
                  for name in ("REPUTATION_DEADLINE_S", "VT_MAX_WAIT_S", "REPUTATION_HTTP_TIMEOUT_S")}

        assert values == {"REPUTATION_DEADLINE_S": 40, "VT_MAX_WAIT_S": 35, "REPUTATION_HTTP_TIMEOUT_S": 15}

    def test_vt_wait_ends_before_the_deadline_and_the_deadline_before_the_orchestrator_gives_up(self):
        from services import orchestrator

        wait = getattr(reputation, "VT_MAX_WAIT_S", None)
        deadline = getattr(reputation, "REPUTATION_DEADLINE_S", None)
        assert wait is not None and deadline is not None, "costanti assenti"
        assert wait < deadline < orchestrator.TIMEOUT


# ── 1. Quota esaurita, richiedenti concorrenti ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="class")
def exhausted_check_vt():
    # Otto `_check_vt` insieme, i quattro posti si liberano solo dopo 1,5 s: nessuno arriva entro l'attesa massima.
    return _run("check_vt", 8, busy=[_WINDOW_S] * _LIMIT)


class TestCheckVtWithExhaustedQuota:
    """`_check_vt` da solo: l'attesa, lucchetto compreso, si ferma a `VT_MAX_WAIT_S` per ognuno degli otto."""

    def test_every_waiter_gives_up_within_the_max_wait(self, exhausted_check_vt):
        _assert_answered_within(exhausted_check_vt, _MAX_WAIT_S + _TOL_S, "attese")

    def test_nobody_gives_up_before_the_max_wait(self, exhausted_check_vt):
        # Il posto si libera a 1,5 s, oltre il limite di 0,7 s: si attende comunque fino al limite, anche in coda al
        # lucchetto, invece di rinunciare subito perché il posto arriverà tardi.
        _bodies(exhausted_check_vt)

        _assert_waited_up_to_the_max_wait(exhausted_check_vt, "attese")

    def test_a_skipped_vt_is_a_complete_dict_with_zeros_and_an_error_text(self, exhausted_check_vt):
        for body in _bodies(exhausted_check_vt):
            _assert_vt_skipped({"virustotal": body})

    def test_a_skipped_vt_makes_no_get_and_takes_no_slot(self, exhausted_check_vt):
        _bodies(exhausted_check_vt)

        assert len(_gets(exhausted_check_vt, "vt")) == 0, "GET a VT per un richiedente che lo ha saltato"
        assert len(_new_slots(exhausted_check_vt)) == 0, "posto VT preso per un richiedente che lo ha saltato"

    def test_no_thread_is_left(self, exhausted_check_vt):
        _assert_no_thread_left(exhausted_check_vt)


@pytest.fixture(scope="class")
def staggered_check_vt():
    # Tre posti si liberano entro l'attesa massima (0,1 / 0,25 / 0,4 s), il quarto ben dopo (1,1 s).
    return _run("check_vt", 8, busy=[0.1, 0.25, 0.4, 1.1])


class TestCheckVtWithStaggeredSlots:
    """Gli otto si contendono tre posti che si liberano in tempo: tre chiamano VT, cinque saltano al limite."""

    def test_slots_freed_within_the_max_wait_are_used(self, staggered_check_vt):
        bodies = _bodies(staggered_check_vt)

        assert len(_gets(staggered_check_vt, "vt")) == 3, f"{len(_gets(staggered_check_vt, 'vt'))} GET a VT, attese 3"
        assert [b for b in bodies if b["error"] is None] == [_observed_vt()] * 3

    def test_nobody_waits_beyond_the_max_wait(self, staggered_check_vt):
        _assert_answered_within(staggered_check_vt, _MAX_WAIT_S + _TOL_S, "attese")

    def test_the_others_are_skipped_without_a_slot(self, staggered_check_vt):
        bodies = _bodies(staggered_check_vt)

        skipped = [b for b in bodies if b["error"] is not None]
        assert len(skipped) == 5, f"VT saltato per {len(skipped)} richiedenti su 8, attesi 5"
        for body in skipped:
            _assert_vt_skipped({"virustotal": body})
        assert len(_new_slots(staggered_check_vt)) == 3

    def test_each_vt_get_waits_for_its_slot(self, staggered_check_vt):
        _bodies(staggered_check_vt)
        frees = sorted(t + _WINDOW_S for t in staggered_check_vt.slots_before)

        walls = sorted(c.wall for c in _gets(staggered_check_vt, "vt"))
        assert all(wall >= free - 0.05 for wall, free in zip(walls, frees, strict=False)), (walls, frees)


class TestQuotaNeverExceeded:
    """Quota (PERF-01): con richiedenti concorrenti e un posto già occupato, in nessuna finestra scorrevole ci sono
    più di `VT_RATE_LIMIT` chiamate VT, contando anche quelle già fatte."""

    def test_no_more_than_the_limit_in_any_sliding_window(self):
        limit, window = 2, 0.5
        run = _run("check_vt", 6, busy=[0.2], window=window, limit=limit)
        _bodies(run)

        times = sorted(run.slots_before + [c.wall for c in _gets(run, "vt")])
        assert len(times) >= limit + 2, f"troppo poche chiamate per mettere alla prova la quota: {len(times)}"
        spans = [round(times[i + limit] - times[i], 3) for i in range(len(times) - limit)]
        assert min(spans) >= window - 0.1, f"{limit + 1} chiamate VT in meno di {window} s: {spans}"


# ── 2. `/reputation` con la quota esaurita ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="class")
def exhausted_requests():
    # Otto richieste insieme, quota esaurita fino a 1,5 s; GET e posti si contano a 1,9 s, quando i posti sono liberi.
    return _run("handler", 8, busy=[_WINDOW_S] * _LIMIT, hold_s=_WINDOW_S + 0.4)


class TestRequestsWithExhaustedQuota:

    def test_every_response_comes_within_the_max_wait(self, exhausted_requests):
        _assert_answered_within(exhausted_requests, _MAX_WAIT_S + _TOL_S, "risposte")

    def test_no_response_skips_vt_before_the_max_wait(self, exhausted_requests):
        _bodies(exhausted_requests)

        _assert_waited_up_to_the_max_wait(exhausted_requests, "risposte")

    def test_vt_is_skipped_and_otx_and_st_are_observed(self, exhausted_requests):
        for body in _bodies(exhausted_requests):
            _assert_vt_skipped(body)
            assert body["otx"] == _observed_otx() and body["securitytrails"] == _OBSERVED_ST

    def test_the_score_leaves_the_skipped_vt_out(self, exhausted_requests):
        for body in _bodies(exhausted_requests):
            assert (body["risk_score"], body["risk_level"], body["error"]) == (10, "low", None)

    def test_no_vt_get_and_no_slot_even_after_the_quota_frees(self, exhausted_requests):
        _bodies(exhausted_requests)

        assert len(_gets(exhausted_requests, "vt")) == 0, "GET a VT per una richiesta che lo ha saltato"
        assert len(_new_slots(exhausted_requests)) == 0, "posto VT preso per una richiesta che lo ha saltato"

    def test_no_thread_is_left(self, exhausted_requests):
        _assert_no_thread_left(exhausted_requests)


class TestRequestsInARowWithExhaustedQuota:
    """Quattro richieste una dopo l'altra, come i domini di un ciclo, con la quota esaurita fino a 1,5 s. Ogni attesa
    vana dura fino al limite (0,7 s), quindi la terza parte quando i posti stanno per liberarsi e li trova, come la
    quarta. Rinunciando subito, le quattro passerebbero tutte a quota esaurita, senza VT."""

    def test_the_later_requests_find_the_freed_slots(self):
        run = _run("handler", 4, busy=[_WINDOW_S] * _LIMIT, serial=True)
        bodies = _bodies(run)

        in_turn = [(round(a.elapsed, 3), b["virustotal"]["error"]) for a, b in zip(run.answers, bodies, strict=True)]
        _assert_vt_skipped(bodies[0])
        assert [b["virustotal"] for b in bodies[2:]] == [_observed_vt()] * 2, f"(durata, `error` di VT): {in_turn}"
        _assert_no_thread_left(run)


# ── 3. OTX e ST lenti mentre VT attende ────────────────────────────────────────────────────────────────────

_SLOW = _plan(otx=_obey(_otx_reply(), _SLOW_S), st=_obey(_Reply(200, _ST_BODY), _SLOW_S))


@pytest.fixture(scope="class")
def slow_sources_no_slot():
    return _run("handler", 1, plan=_SLOW, busy=[_WINDOW_S] * _LIMIT)


class TestSlowOtxAndStWhileVtWaitsInVain:
    """Quota esaurita oltre l'attesa massima, OTX e ST rispondono in 0,38 s: dopo un'attesa VT piena restano
    0,3 s, quindi in fila dietro quell'attesa andrebbero persi."""

    def test_answer_within_the_deadline(self, slow_sources_no_slot):
        _assert_answered_by_the_deadline(slow_sources_no_slot)

    def test_otx_and_st_are_observed_and_vt_is_skipped(self, slow_sources_no_slot):
        (body,) = _bodies(slow_sources_no_slot)

        assert body["otx"] == _observed_otx() and body["securitytrails"] == _OBSERVED_ST
        _assert_vt_skipped(body)

    def test_every_get_fits_in_the_time_left(self, slow_sources_no_slot):
        _bodies(slow_sources_no_slot)

        _assert_gets_fit_in_the_time_left(slow_sources_no_slot)

    def test_no_thread_is_left(self, slow_sources_no_slot):
        _assert_no_thread_left(slow_sources_no_slot)


@pytest.fixture(scope="class")
def slow_sources_with_slot():
    return _run("handler", 1, plan=_SLOW, busy=[0.35, _WINDOW_S, _WINDOW_S, _WINDOW_S])


class TestSlowOtxAndStWhileVtGetsASlot:
    """Un posto si libera a 0,35 s e OTX e ST rispondono in 0,38 s: tutte e tre osservate. In fila dopo VT, ST
    partirebbe con meno di 0,38 s; VT dopo OTX e ST cercherebbe il posto a scadenza passata."""

    def test_answer_within_the_deadline(self, slow_sources_with_slot):
        _assert_answered_by_the_deadline(slow_sources_with_slot)

    def test_all_three_sources_are_observed(self, slow_sources_with_slot):
        (body,) = _bodies(slow_sources_with_slot)

        assert (body["virustotal"], body["otx"], body["securitytrails"]) == (
            _observed_vt(), _observed_otx(), _OBSERVED_ST)
        assert len(_gets(slow_sources_with_slot, "vt")) == 1

    def test_every_get_fits_in_the_time_left(self, slow_sources_with_slot):
        _bodies(slow_sources_with_slot)

        _assert_gets_fit_in_the_time_left(slow_sources_with_slot)

    def test_no_thread_is_left(self, slow_sources_with_slot):
        _assert_no_thread_left(slow_sources_with_slot)


@pytest.fixture(scope="class")
def late_slot():
    return _run("handler", 1, busy=[0.6, _WINDOW_S, _WINDOW_S, _WINDOW_S])


class TestVtGetWithALateSlot:
    """Il posto si libera a 0,6 s, entro l'attesa massima: VT si chiama, con un `timeout` che non va oltre i
    0,4 s che restano (il timeout intero, 0,8 s, porterebbe la GET a 1,4 s)."""

    def test_vt_is_observed(self, late_slot):
        (body,) = _bodies(late_slot)

        assert body["virustotal"] == _observed_vt()

    def test_every_get_fits_in_the_time_left(self, late_slot):
        _bodies(late_slot)

        _assert_gets_fit_in_the_time_left(late_slot)

    def test_no_thread_is_left(self, late_slot):
        _assert_no_thread_left(late_slot)


# ── 4. Fonti mute ──────────────────────────────────────────────────────────────────────────────────────────

_MUTE = _plan(vt=_silent(), otx=_silent(), st=_silent())


@pytest.fixture(scope="class", params=["quota-exhausted", "quota-free"])
def silent_run(request):
    busy = [_WINDOW_S] * _LIMIT if request.param == "quota-exhausted" else []
    return _run("handler", 1, plan=_MUTE, busy=busy)


class TestSilentSources:
    """Nessuna fonte risponde (ognuna fino al proprio `timeout`): in serie con il timeout intero sarebbero
    2,4 s, più l'attesa del posto VT."""

    def test_answer_within_the_deadline(self, silent_run):
        _assert_answered_by_the_deadline(silent_run)

    def test_every_source_is_a_complete_dict_with_an_error(self, silent_run):
        (body,) = _bodies(silent_run)

        for key in ("virustotal", "otx", "securitytrails"):
            _assert_complete_with_error(body, key)
        assert (body["risk_score"], body["risk_level"], body["error"]) == (0, "clean", None)

    def test_every_get_fits_in_the_time_left(self, silent_run):
        _bodies(silent_run)

        _assert_gets_fit_in_the_time_left(silent_run)

    def test_no_thread_is_left(self, silent_run):
        _assert_no_thread_left(silent_run)


# ── 5. GET che non rispettano il proprio timeout ───────────────────────────────────────────────────────────

# Qui la risposta cade proprio alla scadenza: con la scadenza di 2,0 s il margine del 10 % (0,2 s) supera di molto il
# ritardo fisso della risposta sotto carico, e un'attesa dei thread che sfora del 30 % (0,6 s) resta ben oltre.

@pytest.fixture(scope="class")
def deaf_otx():
    return _run("handler", 1, plan=_plan(otx=_deaf(_otx_reply())), hold_s=_DEAF_DEADLINE_S + 0.2,
                deadline=_DEAF_DEADLINE_S)


class TestOneGetIgnoresItsTimeout:
    """OTX risponde solo dopo 5 s qualunque `timeout` riceva: la risposta arriva alla scadenza, con VT e ST."""

    def test_answer_within_the_deadline(self, deaf_otx):
        _assert_answered_by_the_deadline(deaf_otx)

    def test_the_unreached_source_is_a_complete_dict_with_an_error(self, deaf_otx):
        (body,) = _bodies(deaf_otx)

        _assert_complete_with_error(body, "otx")

    def test_vt_answered_in_time_is_kept(self, deaf_otx):
        (body,) = _bodies(deaf_otx)

        assert body["virustotal"] == _observed_vt(), body["virustotal"]
        assert (body["risk_score"], body["risk_level"]) == (40, "medium")
        # ST in fila dopo OTX è ammesso: può restare non raggiunto, ma allora con la forma di una fonte guasta.
        if body["securitytrails"] != _OBSERVED_ST:
            _assert_complete_with_error(body, "securitytrails")

    def test_every_get_fits_in_the_time_left_and_none_starts_late(self, deaf_otx):
        _bodies(deaf_otx)

        _assert_gets_fit_in_the_time_left(deaf_otx)
        assert sorted(c.source for c in deaf_otx.calls if c.source != "st") == ["otx", "vt"]

    def test_no_thread_is_left(self, deaf_otx):
        _assert_no_thread_left(deaf_otx)


@pytest.fixture(scope="class")
def deaf_everything():
    plan = _plan(vt=_deaf(_vt_reply()), otx=_deaf(_otx_reply()), st=_deaf(_Reply(200, _ST_BODY)))
    return _run("handler", 1, plan=plan, deadline=_DEAF_DEADLINE_S)


class TestEveryGetIgnoresItsTimeout:

    def test_answer_within_the_deadline(self, deaf_everything):
        _assert_answered_by_the_deadline(deaf_everything)

    def test_every_source_is_a_complete_dict_with_an_error(self, deaf_everything):
        (body,) = _bodies(deaf_everything)

        for key in ("virustotal", "otx", "securitytrails"):
            _assert_complete_with_error(body, key)

    def test_no_thread_is_left(self, deaf_everything):
        _assert_no_thread_left(deaf_everything)


# ── 6. Attese sotto il limite: sezione completa ───────────────────────────────────────────────────────────

def _expected(vt=None, otx=None, st=None, score=50, level="medium"):
    return {"virustotal": vt or _observed_vt(), "otx": otx or _observed_otx(), "securitytrails": st or _OBSERVED_ST,
            "risk_score": score, "risk_level": level, "error": None}


def _without_timestamp(body, domain):
    assert body["domain"] == domain and isinstance(body.get("timestamp"), str), body
    return {k: v for k, v in body.items() if k not in ("domain", "timestamp")}


_URLS = {"vt": "https://www.virustotal.com/api/v3/domains/{}",
         "otx": "https://otx.alienvault.com/api/v1/indicators/domain/{}/general",
         "st": "https://api.securitytrails.com/v1/domain/{}"}
_HEADERS = {"vt": {"x-apikey": "vt-test-key"}, "otx": {"X-OTX-API-KEY": "otx-test-key"},
            "st": {"APIKEY": "st-test-key"}}


class TestWaitsUnderTheLimit:
    """Quando ogni attesa del posto VT sta sotto il limite, ogni fonte è osservata, con una GET per fonte con URL e
    header dei fornitori, e la GET a VT parte solo a posto libero."""

    def test_a_slot_freed_halfway_gives_the_whole_section(self):
        run = _run("handler", 1, busy=[_MAX_WAIT_S / 2, _WINDOW_S, _WINDOW_S, _WINDOW_S])
        (body,) = _bodies(run)

        assert _without_timestamp(body, run.domains[0]) == _expected()
        (vt,) = _gets(run, "vt")
        assert vt.wall >= run.slots_before[0] + _WINDOW_S - 0.05, "GET a VT con il posto non ancora libero"
        _assert_no_thread_left(run)

    def test_a_sequence_of_requests_gives_whole_sections_and_one_get_per_source(self):
        # Sei richieste in fila con una finestra corta (0,4 s, sotto l'attesa massima): la quinta aspetta che si
        # liberi il posto della richiesta numero uno e lo trova entro il limite, la sesta quello della numero due.
        window = 0.4
        run = _run("handler", 6, window=window, serial=True)
        bodies = _bodies(run)

        assert [_without_timestamp(b, d) for b, d in zip(bodies, run.domains, strict=True)] == [_expected()] * 6
        assert sorted((c.source, c.url, c.headers) for c in run.calls) == sorted(
            (s, _URLS[s].format(d), _HEADERS[s]) for d in run.domains for s in ("vt", "otx", "st"))
        walls = [c.wall for c in _gets(run, "vt")]
        assert walls[4] - walls[0] >= window - 0.1 and walls[5] - walls[1] >= window - 0.1, walls
        _assert_no_thread_left(run)


class TestPerf01Guards:
    """Le guardie di configurazione di PERF-01 scattano subito, senza attesa né salto, anche a quota esaurita."""

    @pytest.mark.parametrize("name, value", [("VT_RATE_LIMIT", 0), ("VT_RATE_LIMIT", -1), ("VT_RATE_WINDOW", 0)])
    def test_the_guard_raises_at_once_even_with_the_quota_exhausted(self, monkeypatch, name, value):
        monkeypatch.setattr(reputation, "VT_MAX_WAIT_S", _MAX_WAIT_S, raising=False)
        monkeypatch.setattr(reputation, "VT_RATE_LIMIT", _LIMIT)
        monkeypatch.setattr(reputation, "VT_RATE_WINDOW", _WINDOW_S)
        monkeypatch.setattr(reputation, "_vt_call_times", [time.time()] * _LIMIT)
        monkeypatch.setattr(reputation, name, value)

        start = time.monotonic()
        with pytest.raises(ValueError, match=name):
            reputation._vt_wait_for_slot()
        assert time.monotonic() - start < _TOL_S

    def test_check_vt_turns_the_guard_into_an_error_without_a_get(self):
        run = _run("check_vt", 1, busy=[_WINDOW_S] * _LIMIT, limit=0)
        (body,) = _bodies(run)

        assert "VT_RATE_LIMIT" in (body["error"] or "")
        assert run.calls == []
        _assert_answered_within(run, _TOL_S, "risposta")


class TestStubbedSlotWait:
    """`_vt_wait_for_slot` sostituita da `lambda: None` (come fanno i test del riporto COL-16): il posto è
    concesso e VT si chiama, qualunque cosa contenga `_vt_call_times`."""

    def test_check_vt_calls_vt(self):
        run = _run("check_vt", 1, busy=[_WINDOW_S] * _LIMIT, stub_wait=True)
        (body,) = _bodies(run)

        assert body == _observed_vt() and len(_gets(run, "vt")) == 1

    def test_the_handler_observes_vt(self):
        run = _run("handler", 1, busy=[_WINDOW_S] * _LIMIT, stub_wait=True)
        (body,) = _bodies(run)

        assert _without_timestamp(body, run.domains[0]) == _expected()
        _assert_no_thread_left(run)


# ── 7. A valle: orchestrator e classificatore veri ─────────────────────────────────────────────────────────

_BASE = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)


def _at(hours, seconds=0):
    return (_BASE + timedelta(hours=hours, seconds=seconds)).isoformat()


def _chain(tmp_path, cycles):
    """Un ciclo per voce di `cycles` (`(plan, busy)`): la sezione dal gestore vero, che l'orchestrator riceve solo
    se arriva entro scadenza + margine (altrimenti `None`, come quando rinuncia), poi `_persist_intel` con lo store
    su `tmp_path` e il `/diff` del classificatore vero. Il dominio è lo stesso in ogni ciclo."""
    from services import orchestrator
    from services.classifier import app as classifier_app

    domain = "acme-typo-0.example"
    out = SimpleNamespace(sections=[], saved=[], alerts=[], diff_status=[], status=[])
    api = TestClient(classifier_app, raise_server_exceptions=False)

    class _Resp:
        def __init__(self, response):
            self._response = response
            self.ok = response.is_success
            self.status_code = response.status_code

        def json(self):
            return self._response.json()

    def post(url, json=None, timeout=None, headers=None):
        response = api.post(url[len(orchestrator.CLASSIFY_URL):], json=json)
        out.diff_status.append(response.status_code)
        return _Resp(response)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orchestrator.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        mp.setattr(orchestrator.intel_store, "HIST_DIR", tmp_path / "history")
        mp.setattr(orchestrator._session, "post", post)
        for n, (plan, busy) in enumerate(cycles):
            run = _run("handler", 1, plan=plan, busy=busy)
            (answer,) = run.answers
            _assert_no_thread_left(run)
            section = None
            if answer.in_time and answer.elapsed <= _DEADLINE_S + _TOL_S and answer.status == 200:
                section = answer.body
                section["timestamp"] = _at(24 * n)
            out.sections.append(section)
            mp.setattr(orchestrator, "now_iso", lambda n=n: _at(24 * n, seconds=30))
            before = len(orchestrator.intel_store.load_history("acme", domain, limit=1000))
            intel = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": section}
            out.status.append(orchestrator._build_collection_status(intel, {"reputation"}))
            orchestrator._persist_intel("acme", domain, "acme.example", intel)
            history = orchestrator.intel_store.load_history("acme", domain, limit=1000)
            out.alerts.append(sorted(f"{a['type']}/{a['severity']}" for e in history[:len(history) - before]
                                     for a in e.get("alerts", [])))
            out.saved.append(orchestrator.intel_store.load_snapshot("acme", domain)["intel"]["reputation"])
    return out


@pytest.fixture(scope="class")
def skipped_chain(tmp_path_factory):
    # Ciclo 0 osservato (VT 3 malevoli, OTX 2 pulse), ciclo 1 con la quota VT esaurita, ciclo 2 osservato.
    return _chain(tmp_path_factory.mktemp("perf05-skip"), [(_plan(), []), (_plan(), [_WINDOW_S] * _LIMIT),
                                                             (_plan(), [])])


class TestDownstreamOfASkippedVt:

    def test_the_orchestrator_gets_the_section_and_the_module_has_not_failed(self, skipped_chain):
        section = skipped_chain.sections[1]

        assert section is not None, "la sezione non è arrivata entro la scadenza: l'orchestrator registra None"
        assert reputation_source_unobserved(section["virustotal"]), section["virustotal"]
        assert collection_failed(section) is False
        assert skipped_chain.status[1] == {"reputation": False}

    def test_vt_is_carried_from_the_previous_cycle_and_the_rest_is_fresh(self, skipped_chain):
        saved = skipped_chain.saved[1]

        assert saved["virustotal"] == _observed_vt()
        assert saved.get("carried_sources") == {"virustotal": {"observed_at": _at(0), "carried_at": _at(24, 30)}}
        assert "carried_over" not in saved, "riportata l'intera sezione, non la sola fonte VT"
        assert (saved["timestamp"], saved["otx"], saved["risk_score"]) == (_at(24), _observed_otx(), 50)

    def test_no_alert_in_any_cycle(self, skipped_chain):
        assert skipped_chain.diff_status and set(skipped_chain.diff_status) == {200}, skipped_chain.diff_status

        assert skipped_chain.alerts == [[], [], []]


class TestDownstreamControl:
    """Controllo della catena: VT letto a zero senza errore nel ciclo di mezzo (un salto scritto male) fa uscire
    al ritorno un `vt_malicious_detected` CRITICAL. Non dipende dall'attesa limitata: dice che la catena vede gli
    alert, quindi «nessun alert» qui sopra non è un controllo vuoto."""

    def test_zeros_written_as_an_observation_raise_a_false_alert_on_return(self, tmp_path):
        chain = _chain(tmp_path, [(_plan(), []), (_plan(vt=_obey(_vt_reply(0))), []), (_plan(), [])])

        assert "vt_malicious_detected/CRITICAL" in chain.alerts[2], chain.alerts


# ── 8. Scheduler in ritardo: un posto VT non preso in tempo non si prende più ─────────────────────────────────

class _OversleepingTime:
    """Il `time` di `services.reputation` con un `sleep` che dura `over` secondi in più: lo scheduler sveglia tardi il
    thread che attende il posto VT."""

    def __init__(self, over):
        self._over = over

    def sleep(self, seconds):
        time.sleep(seconds + self._over)

    def __getattr__(self, name):
        return getattr(time, name)


def _oversleeping(over):
    return lambda mp: mp.setattr(reputation, "time", _OversleepingTime(over))


def _starting_late(delay):
    """Ogni fonte parte `delay` secondi dopo l'inizio della richiesta: lo scheduler avvia tardi il suo thread."""

    def late(check):
        def late_check(domain):
            time.sleep(delay)
            return check(domain)
        return late_check

    def patch(mp):
        for name in ("_check_vt", "_check_otx", "_check_st"):
            mp.setattr(reputation, name, late(getattr(reputation, name)))
    return patch


def _assert_no_late_vt_slot_or_get(run):
    new = [round(t - run.wall0, 3) for t in _new_slots(run)]
    gets = [round(c.wall - run.wall0, 3) for c in _gets(run, "vt")]
    answers = [None if a.elapsed is None else round(a.elapsed, 3) for a in run.answers]
    assert (new, gets) == ([], []), (f"posti VT presi a {new} s e GET a VT a {gets} s dall'inizio, risposta a "
                                      f"{answers} s, scadenza {run.deadline} s, attesa massima {_MAX_WAIT_S} s")


@pytest.fixture(scope="class", params=[0.15, 0.5], ids=["past-the-max-wait", "past-the-deadline"])
def vt_waking_late(request):
    # Un posto si libera a 0,75 s, dopo il limite di 0,7 s. Il sonno dell'attesa dura 0,15 o 0,5 s in più: il thread si
    # sveglia a 0,85 s (oltre il limite, entro la scadenza) o a 1,2 s (oltre la scadenza) e trova il posto libero.
    return _run("handler", 1, busy=[0.75, _WINDOW_S, _WINDOW_S, _WINDOW_S], patch=_oversleeping(request.param))


class TestVtWaitWakingUpLate:
    """Il thread che attende il posto VT si sveglia dopo il limite, quando il posto si è liberato: VT è saltato, e quel
    posto non si prende né durante la richiesta né dopo la risposta, quando il thread finisce da solo. (La durata
    della risposta è dei test sulle fonti mute e sulle GET sorde: qui conta il posto.)"""

    def test_vt_is_skipped(self, vt_waking_late):
        (body,) = _bodies(vt_waking_late)

        _assert_vt_skipped(body)

    def test_the_late_slot_is_never_taken_and_vt_is_not_called(self, vt_waking_late):
        _bodies(vt_waking_late)

        _assert_no_late_vt_slot_or_get(vt_waking_late)

    def test_no_thread_is_left(self, vt_waking_late):
        _assert_no_thread_left(vt_waking_late)


@pytest.fixture(scope="class")
def sources_starting_after_the_deadline():
    # Quota libera; le tre fonti partono a 1,2 s, dopo la scadenza di 1,0 s.
    return _run("handler", 1, patch=_starting_late(_DEADLINE_S + 0.2))


class TestSourcesStartingAfterTheDeadline:
    """Lo scheduler avvia le fonti dopo la scadenza: la risposta ha tre fonti non raggiunte, e le fonti partite tardi
    non prendono un posto VT e non fanno GET."""

    def test_every_source_is_a_complete_dict_with_an_error(self, sources_starting_after_the_deadline):
        (body,) = _bodies(sources_starting_after_the_deadline)

        for key in ("virustotal", "otx", "securitytrails"):
            _assert_complete_with_error(body, key)

    def test_no_get_starts_after_the_deadline(self, sources_starting_after_the_deadline):
        _bodies(sources_starting_after_the_deadline)

        late = [(c.source, round(c.wall - sources_starting_after_the_deadline.wall0, 3), c.timeout)
                for c in sources_starting_after_the_deadline.calls]
        assert late == [], f"GET (fonte, partenza dall'inizio, timeout) a scadenza passata: {late}"

    def test_no_vt_slot_is_taken_after_the_deadline(self, sources_starting_after_the_deadline):
        _bodies(sources_starting_after_the_deadline)

        _assert_no_late_vt_slot_or_get(sources_starting_after_the_deadline)

    def test_no_thread_is_left(self, sources_starting_after_the_deadline):
        _assert_no_thread_left(sources_starting_after_the_deadline)


@pytest.fixture(scope="class")
def vt_starting_close_to_the_deadline():
    # Le fonti partono a 0,5 s: alla scadenza mancano 0,5 s, meno dell'attesa massima (0,7 s). La quota è esaurita e
    # il primo posto si libera a 1,1 s, dopo la scadenza ma entro 0,5 + 0,7 s.
    return _run("handler", 1, busy=[_DEADLINE_S + 0.1, _WINDOW_S, _WINDOW_S, _WINDOW_S], patch=_starting_late(0.5))


class TestVtStartingWithLessThanTheMaxWaitLeft:
    """VT parte quando alla scadenza manca meno dell'attesa massima: l'attesa del posto finisce alla scadenza, e il
    posto che si libera dopo non si prende."""

    def test_vt_is_skipped_without_a_slot_or_a_get(self, vt_starting_close_to_the_deadline):
        (body,) = _bodies(vt_starting_close_to_the_deadline)

        _assert_vt_skipped(body)
        _assert_no_late_vt_slot_or_get(vt_starting_close_to_the_deadline)

    def test_no_thread_is_left(self, vt_starting_close_to_the_deadline):
        _assert_no_thread_left(vt_starting_close_to_the_deadline)
