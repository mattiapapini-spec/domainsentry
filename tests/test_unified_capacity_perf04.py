"""PERF-04: nel processo unificato le richieste ai cinque collettori non possono occupare tutto il pool di thread.

I gestori sincroni di tutti i servizi (collettori, dashboard, login, `/health`) condividono i 40 thread del pool di
anyio. Richieste lente a `/dns`, `/cert`, `/http`, `/whois` e `/reputation` li occupavano tutti, e il resto del
servizio, sonda di salute compresa, aspettava. Ora un filtro ASGI, prima di prendere un thread, ammette al più 20
richieste ai collettori insieme, 8 per collettore e 4 per la reputazione; le altre ricevono subito un 503 e il posto
torna libero quando il gestore finisce davvero, non quando il chiamante smette di aspettare. Il resto del servizio non
passa dal filtro.
"""

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import unified
from services import whois_intel as whois_service


# ── Il difetto, nel processo unificato vero ──────────────────────────────────────────────────

@pytest.fixture
def slow_whois(monkeypatch):
    def _lookup(domain):
        time.sleep(1.5)
        return SimpleNamespace(registrar="R", creation_date=None, expiration_date=None, updated_date=None, status=None,
                               name_servers=None, name="N", org="O", country=None, emails=None, dnssec=None)

    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
    monkeypatch.setattr(whois_service, "_whois_library_lookup", _lookup)
    monkeypatch.setattr(whois_service, "_cache", {})
    monkeypatch.setattr(whois_service, "_cache_order", [])
    monkeypatch.setattr(whois_service, "WHOIS_DELAY", 0.0)


class TestPERF04TheRestOfTheServiceStaysReachable:
    def test_health_answers_while_slow_collector_requests_flood_the_process(self, slow_whois):
        statuses = []
        lock = threading.Lock()
        with TestClient(unified.app) as client:
            def _flood(i):
                code = client.get("/whois", params={"domain": f"acme-typo{i}.com"}).status_code
                with lock:
                    statuses.append(code)

            threads = [threading.Thread(target=_flood, args=(i,)) for i in range(45)]
            for t in threads:
                t.start()
            time.sleep(0.4)
            t0 = time.monotonic()
            health = client.get("/health")
            health_s = time.monotonic() - t0
            for t in threads:
                t.join(20)

        assert health.status_code == 200
        assert health_s < 0.5, health_s
        assert statuses.count(200) <= 8, statuses
        assert statuses.count(503) >= 45 - 8, statuses


# ── Il filtro, a livello ASGI ────────────────────────────────────────────────────────────────

def _capacity():
    return getattr(unified, "_COLLECTOR_CAPACITY", None)


class _Held:
    """App ASGI finta: ogni richiesta resta in corso finché il test non libera l'evento."""

    def __init__(self):
        self.release = asyncio.Event()
        self.entered = 0

    async def __call__(self, scope, receive, send):
        self.entered += 1
        await self.release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _request(app, path):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [], "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000), "scheme": "http",
             "root_path": "", "http_version": "1.1"}
    await app(scope, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def filtered():
    inner = _Held()
    unified._COLLECTOR_CAPACITY.reset()
    app = unified.CollectorCapacityMiddleware(inner)
    yield app, inner
    unified._COLLECTOR_CAPACITY.reset()


class TestPERF04Limits:
    def test_the_middleware_is_installed_on_the_unified_app(self):
        assert any(m.cls is getattr(unified, "CollectorCapacityMiddleware", None) for m in unified.app.user_middleware)

    @pytest.mark.parametrize("path, cap", [("/dns", 8), ("/cert", 8), ("/http", 8), ("/whois", 8), ("/reputation", 4)])
    def test_each_collector_has_its_own_cap(self, filtered, path, cap):
        app, inner = filtered

        async def scenario():
            tasks = [asyncio.create_task(_request(app, path)) for _ in range(cap + 3)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            return entered, await asyncio.gather(*tasks)

        entered, codes = _run(scenario())

        assert entered == cap
        assert sorted(codes) == [200] * cap + [503] * 3

    def test_all_collectors_together_have_a_cap_of_twenty(self, filtered):
        app, inner = filtered
        paths = ["/dns"] * 8 + ["/cert"] * 8 + ["/http"] * 8 + ["/whois"] * 8

        async def scenario():
            tasks = [asyncio.create_task(_request(app, p)) for p in paths]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            return entered, await asyncio.gather(*tasks)

        entered, codes = _run(scenario())

        assert entered == 20
        assert codes.count(503) == len(paths) - 20

    def test_a_place_comes_back_when_the_request_ends(self, filtered):
        app, inner = filtered

        async def scenario():
            first = [asyncio.create_task(_request(app, "/reputation")) for _ in range(4)]
            await asyncio.sleep(0.05)
            inner.release.set()
            await asyncio.gather(*first)
            return await _request(app, "/reputation")

        assert _run(scenario()) == 200
        assert _capacity().in_use() == 0

    def test_a_place_comes_back_when_the_handler_raises(self, filtered):
        app, _ = filtered

        async def boom(scope, receive, send):
            raise RuntimeError("x")

        broken = unified.CollectorCapacityMiddleware(boom)
        with pytest.raises(RuntimeError):
            _run(_request(broken, "/dns"))
        assert _capacity().in_use() == 0

    @pytest.mark.parametrize("path", ["/health", "/dashboard", "/auth/login", "/classify/variant", "/twist", "/dnsx"])
    def test_other_paths_do_not_pass_through_the_filter(self, filtered, path):
        app, inner = filtered

        async def scenario():
            tasks = [asyncio.create_task(_request(app, path)) for _ in range(30)]
            await asyncio.sleep(0.05)
            entered = inner.entered
            inner.release.set()
            await asyncio.gather(*tasks)
            return entered

        assert _run(scenario()) == 30

    def test_a_refused_request_gets_a_503_with_retry_after_and_no_thread(self, filtered):
        app, inner = filtered
        heads = []

        async def scenario():
            held = [asyncio.create_task(_request(app, "/reputation")) for _ in range(4)]
            await asyncio.sleep(0.05)
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            scope = {"type": "http", "method": "GET", "path": "/reputation", "raw_path": b"/reputation",
                     "query_string": b"", "headers": [], "client": ("127.0.0.1", 1),
                     "server": ("127.0.0.1", 8000), "scheme": "http", "root_path": "", "http_version": "1.1"}
            await app(scope, receive, send)
            heads.extend(sent)
            inner.release.set()
            await asyncio.gather(*held)

        _run(scenario())

        start = next(m for m in heads if m["type"] == "http.response.start")
        assert start["status"] == 503
        assert (b"retry-after", b"5") in start["headers"]
        assert inner.entered == 4


class TestPERF04RefusalsAreLoggedSparingly:
    def test_a_flood_of_refusals_logs_one_line_with_the_counts(self, filtered, caplog):
        app, inner = filtered

        async def scenario():
            held = [asyncio.create_task(_request(app, "/reputation")) for _ in range(4)]
            await asyncio.sleep(0.05)
            refused = await asyncio.gather(*[_request(app, "/reputation") for _ in range(50)])
            inner.release.set()
            await asyncio.gather(*held)
            return refused

        with caplog.at_level("WARNING", logger="domainsentry"):
            refused = _run(scenario())

        lines = [r.getMessage() for r in caplog.records if r.name == "domainsentry"]
        assert refused == [503] * 50
        assert len(lines) == 1 and "/reputation 1" in lines[0], lines
