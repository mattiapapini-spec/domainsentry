"""PERF-04 (tetto ai processi `dig`): in tutto il processo non girano più di `DIG_MAX_PROCESSES` `dig` insieme.

Dopo SEC-29 una richiesta `/dns` avvia fino a 10 `dig` insieme (7 per i tipi base, anche con `full=false`), e nessun
tetto di processo li contiene: richieste concorrenti moltiplicano i processi. Una query che non trova un posto entro
il tempo che le resta è `unknown`, come ogni query senza esito, mai "nessun record"; l'attesa del posto si toglie dal
tempo del processo, così la scadenza di SEC-29 resta quella. Nessun `dig` reale: `subprocess.run` finto.
"""

import subprocess
import threading
import time

import pytest

from shared import utils

_CAP = getattr(utils, "DIG_MAX_PROCESSES", 20)
_ANSWER = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242\n"
           ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
           "acme-crop.example. A 192.0.2.10\n")


class _FakeDig:
    """`subprocess.run` finto: conta i `dig` vivi insieme e annota il `timeout` ricevuto."""

    def __init__(self, hold=0.2, fail=False):
        self.hold, self.fail = hold, fail
        self.lock = threading.Lock()
        self.alive = self.peak = self.started = 0
        self.timeouts = []

    def __call__(self, argv, **kwargs):
        with self.lock:
            self.alive += 1
            self.started += 1
            self.peak = max(self.peak, self.alive)
            self.timeouts.append(kwargs.get("timeout"))
        try:
            time.sleep(self.hold)
            if self.fail:
                raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
            return subprocess.CompletedProcess(argv, 0, stdout=_ANSWER, stderr="")
        finally:
            with self.lock:
                self.alive -= 1


@pytest.fixture
def fake_dig(monkeypatch):
    def _install(**kwargs):
        fake = _FakeDig(**kwargs)
        monkeypatch.setattr(utils.subprocess, "run", fake)
        return fake
    return _install


def _many(n, limit):
    results = [None] * n

    def _one(i):
        results[i] = utils.dig_lookup("acme-crop.example", "A", 5, limit=limit)

    threads = [threading.Thread(target=_one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results


class TestPERF04DigProcessCap:
    def test_concurrent_lookups_never_run_more_dig_than_the_cap(self, fake_dig):
        fake = fake_dig(hold=0.2)

        results = _many(3 * _CAP, limit=20)

        assert fake.peak <= _CAP, fake.peak
        assert results == [("ok", ["192.0.2.10"])] * (3 * _CAP)

    def test_a_lookup_without_a_place_in_time_is_unknown_and_starts_nothing(self, fake_dig):
        fake = fake_dig(hold=1.5)
        holders = [threading.Thread(target=utils.dig_lookup, args=("acme-crop.example", "A", 5),
                                    kwargs={"limit": 20}) for _ in range(_CAP)]
        for t in holders:
            t.start()
        time.sleep(0.3)

        started_before = fake.started
        t0 = time.monotonic()
        late = utils.dig_lookup("acme-crop.example", "A", 5, limit=0.3)
        waited = time.monotonic() - t0

        assert late == ("unknown", [])
        assert fake.started == started_before
        assert waited < 1.0
        for t in holders:
            t.join(10)

    def test_the_wait_for_a_place_is_taken_from_the_process_time(self, fake_dig):
        fake = fake_dig(hold=0.5)
        holders = [threading.Thread(target=utils.dig_lookup, args=("acme-crop.example", "A", 5),
                                    kwargs={"limit": 20}) for _ in range(_CAP)]
        for t in holders:
            t.start()
        time.sleep(0.1)

        assert utils.dig_lookup("acme-crop.example", "A", 5, limit=3.0) == ("ok", ["192.0.2.10"])
        assert fake.timeouts[-1] <= 3.0 - 0.3, fake.timeouts[-1]
        for t in holders:
            t.join(10)

    def test_a_failed_dig_gives_its_place_back(self, fake_dig):
        fake_dig(hold=0.0, fail=True)
        assert [utils.dig_lookup("acme-crop.example", "A", 5, limit=5) for _ in range(_CAP + 2)] \
            == [("unknown", [])] * (_CAP + 2)

        fake = fake_dig(hold=0.0)
        assert _many(_CAP, limit=2) == [("ok", ["192.0.2.10"])] * _CAP
        assert fake.peak <= _CAP

    def test_without_a_limit_the_process_keeps_its_own_ceiling(self, fake_dig):
        fake = fake_dig(hold=0.0)

        assert utils.dig_lookup("acme-crop.example", "A", 5) == ("ok", ["192.0.2.10"])
        assert fake.timeouts[-1] == 15
