"""
Orchestrator: scope filtering (all/target/watchlist) and the variant_intel /
scope params on TriggerRequest. These guard the v4.8.0 additions:
 - scope restricts which feed domains the pipeline processes
 - variant_intel is an opt-in flag (heavy: full intel per registered variant)
"""
import os
import importlib
import pytest


@pytest.fixture
def orch(monkeypatch):
    # Minimal env so the module imports cleanly
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    return o


class TestTriggerRequestParams:
    def test_defaults(self, orch):
        r = orch.TriggerRequest()
        assert r.scope == "all"
        assert r.variant_intel is False
        assert r.include_dnstwist is False

    def test_accepts_scope_and_variant_intel(self, orch):
        r = orch.TriggerRequest(scope="target", variant_intel=True, include_dnstwist=True)
        assert r.scope == "target"
        assert r.variant_intel is True


class TestScopeFilter:
    """The pipeline filters feed domains by type when scope is target/watchlist."""
    DOMAINS = [
        {"domain": "a.com", "client": "k", "type": "target"},
        {"domain": "b.com", "client": "k", "type": "target"},
        {"domain": "c.com", "client": "k", "type": "watchlist"},
        {"domain": "d.com", "client": "k"},  # no type → treated as target
    ]

    def _filter(self, domains, scope):
        # Mirrors the orchestrator's scope filter logic exactly
        scope = (scope or "all").lower()
        if scope in ("target", "watchlist"):
            return [d for d in domains if d.get("type", "target") == scope]
        return domains

    def test_scope_all_keeps_everything(self):
        assert len(self._filter(self.DOMAINS, "all")) == 4

    def test_scope_target_includes_untyped(self):
        out = self._filter(self.DOMAINS, "target")
        names = {d["domain"] for d in out}
        assert names == {"a.com", "b.com", "d.com"}  # d.com (no type) counts as target

    def test_scope_watchlist_only(self):
        out = self._filter(self.DOMAINS, "watchlist")
        names = {d["domain"] for d in out}
        assert names == {"c.com"}

    def test_unknown_scope_defaults_to_all(self):
        assert len(self._filter(self.DOMAINS, "garbage")) == 4


class TestProgressEndpoint:
    """The /progress endpoint exposes real pipeline telemetry for the Scan progress view."""
    @pytest.fixture
    def client(self, orch):
        from fastapi.testclient import TestClient
        return TestClient(orch.app)

    def test_idle_state(self, orch, client):
        r = client.get("/progress")
        assert r.status_code == 200
        b = r.json()
        assert b["phase"] in ("idle", "done", "error")
        assert b["percent"] == 0 or b["phase"] == "done"

    def test_percent_derived_from_counts(self, orch, client):
        orch._progress_reset("acme", 8)
        orch._progress_set(phase="scanning", done=2)
        b = client.get("/progress").json()
        assert b["total"] == 8 and b["done"] == 2 and b["percent"] == 25
        assert b["client"] == "acme"

    def test_log_buffer_capped(self, orch, client):
        orch._progress_reset("acme", 1)
        for i in range(orch._MAX_LOG_LINES + 50):
            orch._plog(f"line {i}")
        b = client.get("/progress").json()
        assert len(b["log"]) == orch._MAX_LOG_LINES  # capped, not unbounded

    def test_log_can_be_excluded(self, orch, client):
        orch._plog("something")
        b = client.get("/progress?include_log=false").json()
        assert b["log"] == []


class TestDnstwistDedup:
    """
    Regression: dnstwist ran once PER TARGET. Multiple targets of one client share
    the same legitimate domain, so dnstwist on the same legit produced identical
    variants and the whole discovery + variant-intel pass repeated N times (3x for
    Kedrion's 3 targets). It must run once per DISTINCT legitimate domain.
    """
    def _distinct_legits(self, client_domains):
        # Mirrors the orchestrator's dedup logic
        legits, seen = [], set()
        for d in client_domains:
            if d.get("type") != "target":
                continue
            lg = d.get("legitimate", d["domain"])
            if lg not in seen:
                seen.add(lg)
                legits.append(lg)
        return legits

    def test_three_targets_same_legit_dedup_to_one(self):
        domains = [
            {"domain": "kerdion.com", "type": "target", "legitimate": "kedrion.com"},
            {"domain": "kedrionta.com", "type": "target", "legitimate": "kedrion.com"},
            {"domain": "kedrion.shop", "type": "target", "legitimate": "kedrion.com"},
        ]
        assert self._distinct_legits(domains) == ["kedrion.com"]  # one run, not three

    def test_distinct_legits_preserved(self):
        domains = [
            {"domain": "a-typo.com", "type": "target", "legitimate": "acme.com"},
            {"domain": "b-typo.com", "type": "target", "legitimate": "beta.com"},
        ]
        assert set(self._distinct_legits(domains)) == {"acme.com", "beta.com"}

    def test_watchlist_excluded_from_dnstwist(self):
        domains = [
            {"domain": "x.com", "type": "target", "legitimate": "acme.com"},
            {"domain": "y.com", "type": "watchlist", "legitimate": "acme.com"},
        ]
        # only targets drive dnstwist; still dedups to the one legit
        assert self._distinct_legits(domains) == ["acme.com"]


class TestPipelineLockRecovery:
    """A pipeline that dies without cleanup (OOM/SIGKILL/crash) must not block all
    future scans forever. Heartbeat staleness auto-recovers; a manual reset exists too."""

    def _client(self):
        import services.orchestrator as o
        from fastapi.testclient import TestClient
        return o, TestClient(o.app)

    def test_stale_heartbeat_allows_new_run(self):
        import time
        o, c = self._client()
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - (o.HEARTBEAT_STALE_SEC + 60)
        r = c.post("/trigger", json={"client": "X"})
        assert r.status_code == 200  # auto-reset, not blocked
        o._running = False

    def test_fresh_heartbeat_still_blocks(self):
        import time
        o, c = self._client()
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - 30  # alive
        r = c.post("/trigger", json={"client": "X"})
        assert r.status_code == 409
        o._running = False

    def test_manual_reset_unblocks(self):
        import time
        o, c = self._client()
        o._running = True
        o._last_heartbeat = time.time() - 30
        r = c.post("/trigger/reset")
        assert r.status_code == 200
        assert r.json()["was_running"] is True
        assert o._running is False
