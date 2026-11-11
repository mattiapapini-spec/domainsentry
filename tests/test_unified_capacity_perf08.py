"""PERF-08 e variante B2: la scansione dell'orchestrator ha posti riservati, e quelli che ha abbandonato non li tengono.

Col filtro di PERF-04 un flood anonimo sui collettori occupava anche i posti che servono alla scansione legittima, che
riceveva 503 come chiunque. Ora 8 posti sono riservati alle richieste dell'orchestrator, riconosciute da un
contrassegno casuale generato all'avvio del processo (`X-DomainSentry-Scan`); con la riserva piena la scansione usa i
posti anonimi. Variante B2 (decisione di Mat): una richiesta della scansione più vecchia di `SERVICE_TIMEOUT`
dell'orchestrator è già stata abbandonata, perché l'orchestrator rinuncia sempre a quella soglia; il suo thread però
è ancora occupato. Passa allora in un conto a parte con tetto 4 e lascia una riga nel log, così la riserva torna alla
scansione viva. In tutto non ci sono mai più di 20 + 8 + 4 = 32 richieste ai collettori in corso.
"""

import asyncio
import os
import subprocess
import sys

import pytest

import unified
from services import orchestrator

_SCAN = (b"x-domainsentry-scan", unified.SCAN_TOKEN.encode()) if hasattr(unified, "SCAN_TOKEN") else None


class _Held:
    def __init__(self):
        self.release = asyncio.Event()
        self.entered = 0

    async def __call__(self, scope, receive, send):
        self.entered += 1
        await self.release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _request(app, path, headers=()):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": list(headers), "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000),
             "scheme": "http", "root_path": "", "http_version": "1.1"}
    await app(scope, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def filtered(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(unified._COLLECTOR_CAPACITY, "clock", clock, raising=False)
    unified._COLLECTOR_CAPACITY.reset()
    inner = _Held()
    yield unified.CollectorCapacityMiddleware(inner), inner, clock
    unified._COLLECTOR_CAPACITY.reset()


def _anonymous_flood():
    return ["/dns"] * 8 + ["/cert"] * 8 + ["/http"] * 4


class TestPERF08Reserve:
    def test_the_scan_gets_in_while_anonymous_callers_fill_their_places(self, filtered):
        app, inner, _ = filtered

        async def scenario():
            flood = [asyncio.create_task(_request(app, p)) for p in _anonymous_flood()]
            await asyncio.sleep(0.05)
            anon_refused = await _request(app, "/whois")
            scans = [asyncio.create_task(_request(app, "/whois", [_SCAN])) for _ in range(8)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            return anon_refused, entered, await asyncio.gather(*scans), await asyncio.gather(*flood)

        anon_refused, entered, scans, flood = asyncio.run(scenario())

        assert anon_refused == 503
        assert entered == 20 + 8
        assert scans == [200] * 8 and flood == [200] * 20

    def test_with_its_reserve_full_the_scan_uses_the_anonymous_places(self, filtered):
        app, inner, _ = filtered

        async def scenario():
            scans = [asyncio.create_task(_request(app, "/dns", [_SCAN])) for _ in range(8 + 8 + 1)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            return entered, await asyncio.gather(*scans)

        entered, codes = asyncio.run(scenario())

        assert entered == 16  # 8 riservati, poi gli 8 anonimi di /dns
        assert codes.count(503) == 1

    @pytest.mark.parametrize("header", [(b"x-domainsentry-scan", b"indovinato"), (b"x-domainsentry-scan", b""),
                                        (b"x-other", b"x")])
    def test_without_the_right_mark_a_request_is_anonymous(self, filtered, header):
        app, inner, _ = filtered

        async def scenario():
            flood = [asyncio.create_task(_request(app, p)) for p in _anonymous_flood()]
            await asyncio.sleep(0.05)
            code = await _request(app, "/whois", [header])
            inner.release.set()
            await asyncio.gather(*flood)
            return code

        assert asyncio.run(scenario()) == 503

    def test_the_mark_is_random_per_process_and_sent_by_the_orchestrator(self):
        # In un processo nuovo: altri test ricaricano `services.orchestrator`, che ricrea la sessione.
        probe = ("import unified; from services import orchestrator as o; "
                 "print(o._session.headers.get('X-DomainSentry-Scan') == unified.SCAN_TOKEN, unified.SCAN_TOKEN)")
        runs = [subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=60,
                               env={**os.environ, "PYTHONPATH": "."}) for _ in range(2)]
        lines = [r.stdout.strip().splitlines()[-1].split() for r in runs]

        assert [line[0] for line in lines] == ["True", "True"], [r.stderr[-500:] for r in runs]
        assert len(lines[0][1]) >= 32 and lines[0][1] != lines[1][1]


class TestB2AbandonedScanRequests:
    def test_an_abandoned_scan_request_leaves_the_reserve_to_the_live_scan(self, filtered, caplog):
        app, inner, clock = filtered

        async def scenario():
            old = [asyncio.create_task(_request(app, "/http", [_SCAN])) for _ in range(8)]
            flood = [asyncio.create_task(_request(app, p)) for p in _anonymous_flood()]
            await asyncio.sleep(0.05)
            clock.now += orchestrator.TIMEOUT + 1
            live = [asyncio.create_task(_request(app, "/dns", [_SCAN])) for _ in range(4)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            return entered, await asyncio.gather(*live), await asyncio.gather(*old), await asyncio.gather(*flood)

        with caplog.at_level("WARNING", logger="domainsentry"):
            entered, live, old, flood = asyncio.run(scenario())

        assert live == [200] * 4
        assert entered == 8 + 20 + 4
        assert old == [200] * 8 and flood == [200] * 20
        lines = [r.getMessage() for r in caplog.records if r.name == "domainsentry" and "abbandonat" in r.getMessage()]
        assert len(lines) == 4, lines

    def test_at_most_four_abandoned_requests_leave_the_reserve(self, filtered):
        app, inner, clock = filtered

        async def scenario():
            old = [asyncio.create_task(_request(app, "/http", [_SCAN])) for _ in range(8)]
            flood = [asyncio.create_task(_request(app, p)) for p in _anonymous_flood()]
            await asyncio.sleep(0.05)
            clock.now += orchestrator.TIMEOUT + 1
            live = [asyncio.create_task(_request(app, "/dns", [_SCAN])) for _ in range(6)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            in_use = unified._COLLECTOR_CAPACITY.in_use()
            inner.release.set()
            return entered, in_use, await asyncio.gather(*live), old, flood

        entered, in_use, live, old, flood = asyncio.run(scenario())

        assert entered == 32 and in_use == 32
        assert sorted(live) == [200] * 4 + [503] * 2

    def test_a_scan_request_younger_than_the_timeout_keeps_its_reserved_place(self, filtered):
        app, inner, clock = filtered

        async def scenario():
            held = [asyncio.create_task(_request(app, "/http", [_SCAN])) for _ in range(8)]
            flood = [asyncio.create_task(_request(app, p)) for p in _anonymous_flood()]
            await asyncio.sleep(0.05)
            clock.now += orchestrator.TIMEOUT - 1
            code = await _request(app, "/dns", [_SCAN])
            inner.release.set()
            await asyncio.gather(*held, *flood)
            return code

        assert asyncio.run(scenario()) == 503

    def test_every_place_comes_back_whatever_bucket_it_ended_in(self, filtered):
        app, inner, clock = filtered

        async def scenario():
            old = [asyncio.create_task(_request(app, "/http", [_SCAN])) for _ in range(8)]
            await asyncio.sleep(0.05)
            clock.now += orchestrator.TIMEOUT + 1
            live = [asyncio.create_task(_request(app, "/dns", [_SCAN])) for _ in range(2)]
            await asyncio.sleep(0.05)
            inner.release.set()
            await asyncio.gather(*old, *live)

        asyncio.run(scenario())

        assert unified._COLLECTOR_CAPACITY.in_use() == 0
