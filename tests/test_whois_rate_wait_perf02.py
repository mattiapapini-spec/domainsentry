"""PERF-02 (WHOIS): l'attesa del ritmo fra le query non tiene il lucchetto e ha un tetto.

Prima `whois_check` dormiva fino al proprio turno tenendo `_rate_lock`: le richieste concorrenti si mettevano in fila
una dietro l'altra, ognuna con un thread del pool condiviso del processo unificato, e la k-esima aspettava circa
k × `WHOIS_DELAY` senza limite. Ora il turno si prenota sotto il lucchetto e si aspetta fuori; chi dovrebbe aspettare
più di `WHOIS_MAX_WAIT_S` risponde subito con un errore fisso (modulo non raccolto, riportato dal ciclo precedente),
come VirusTotal senza posto nella quota (PERF-05). Lo spazio minimo fra due query resta `WHOIS_DELAY`.
"""

import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from services import whois_intel as whois_service

_BUSY = getattr(whois_service, "WHOIS_RATE_BUSY_ERROR", "WHOIS lookup skipped: no query slot within the wait limit")


@pytest.fixture
def whois(monkeypatch):
    started = []
    lock = threading.Lock()

    def _lookup(domain):
        with lock:
            started.append(time.monotonic())
        return SimpleNamespace(registrar="Registrar Esempio", creation_date="2020-01-01", expiration_date=None,
                               updated_date=None, status=None, name_servers=None, name="Reg Name",
                               org="Reg Name Srl", country="ZZ", emails=None, dnssec=None)

    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
    monkeypatch.setattr(whois_service, "_whois_library_lookup", _lookup)
    monkeypatch.setattr(whois_service, "_cache", {})
    monkeypatch.setattr(whois_service, "_cache_order", [])
    monkeypatch.setattr(whois_service, "_last_query_time", 0.0)
    monkeypatch.setattr(whois_service, "WHOIS_DELAY", 0.2)
    monkeypatch.setattr(whois_service, "WHOIS_MAX_WAIT_S", 0.5, raising=False)
    return SimpleNamespace(api=TestClient(whois_service.app), started=started)


def _parallel(api, domains):
    out = [None] * len(domains)

    def _one(i):
        t0 = time.monotonic()
        body = api.get("/whois", params={"domain": domains[i]}).json()
        out[i] = (body.get("error"), time.monotonic() - t0)

    threads = [threading.Thread(target=_one, args=(i,)) for i in range(len(domains))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return out


class TestPERF02WaitIsBounded:
    def test_requests_beyond_the_wait_limit_answer_at_once_with_a_fixed_error(self, whois):
        out = _parallel(whois.api, [f"acme-typo{i}.com" for i in range(10)])

        served = [o for o in out if o[0] is None]
        busy = [o for o in out if o[0] == _BUSY]
        assert len(served) + len(busy) == 10, out
        assert 1 <= len(served) <= 4, out
        assert busy and max(elapsed for _, elapsed in busy) < 0.3, out

    def test_the_minimum_spacing_between_queries_stays(self, whois):
        _parallel(whois.api, [f"acme-typo{i}.com" for i in range(10)])

        starts = sorted(whois.started)
        gaps = [b - a for a, b in zip(starts, starts[1:], strict=False)]
        assert gaps and min(gaps) >= 0.2 - 0.02, gaps

    def test_a_busy_answer_is_not_cached(self, whois):
        _parallel(whois.api, [f"acme-typo{i}.com" for i in range(10)])
        busy_domain = next(d for d in (f"acme-typo{i}.com" for i in range(10))
                           if d not in whois_service._cache)
        time.sleep(0.6)

        body = whois.api.get("/whois", params={"domain": busy_domain}).json()

        assert body["error"] is None and body["registrar"] == "Registrar Esempio"


class TestPERF02ClockAndBudget:
    def test_the_turn_does_not_follow_the_wall_clock(self, whois, monkeypatch):
        # Una prima query registra il turno con l'orologio che il codice usa; poi l'orologio di sistema torna indietro
        # di un'ora. Un salto all'indietro non deve bloccare le query per tutta la sua durata.
        assert whois.api.get("/whois", params={"domain": "acme-typo1.com"}).json()["error"] is None
        real_time = time.time
        monkeypatch.setattr(whois_service.time, "time", lambda: real_time() - 3600)
        time.sleep(0.25)

        body = whois.api.get("/whois", params={"domain": "acme-typo2.com"}).json()

        assert body["error"] is None

    def test_the_worst_case_stays_under_the_orchestrator_timeout(self):
        from services import orchestrator
        worst = (whois_service.WHOIS_MAX_WAIT_S + whois_service.WHOIS_LOOKUP_DEADLINE_S
                 + 2 * whois_service.WHOIS_PARSE_TIMEOUT_S)

        assert worst < orchestrator.TIMEOUT, worst


class TestPERF02LockIsNotHeldWhileWaiting:
    def test_the_rate_lock_is_free_while_a_request_waits_for_its_turn(self, whois, monkeypatch):
        monkeypatch.setattr(whois_service, "WHOIS_DELAY", 1.0)
        monkeypatch.setattr(whois_service, "WHOIS_MAX_WAIT_S", 2.0, raising=False)
        monkeypatch.setattr(whois_service, "_last_query_time", time.monotonic())
        waiter = threading.Thread(target=whois.api.get, args=("/whois",), kwargs={"params": {"domain": "acme-typo.com"}})
        waiter.start()
        time.sleep(0.3)

        free = whois_service._rate_lock.acquire(timeout=0.1)
        if free:
            whois_service._rate_lock.release()
        waiter.join(10)

        assert free
