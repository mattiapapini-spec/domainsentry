"""OPS-06: con `INTEL_STORE` spento la pipeline non scrive snapshot né storia, neanche per le varianti di dnstwist.

Il ciclo dei domini del feed controllava il flag, il ramo `variant_intel` no: chiamava `_persist_intel` per ogni
variante risolvente, che salvava lo snapshot e, con un precedente, chiedeva il `/diff` e aggiungeva la storia.
"""

import importlib

import pytest

from tests.test_orchestrator import _R

_FEED = {"domains": [{"domain": "acme-corp.example", "client": "T-001", "type": "target",
                      "legitimate": "acme-corp.example"}]}
_TWIST = {"registered_variants": 1, "variants": [
    {"domain": "acme-crop.example", "fuzzer": "transposition", "dns_a": True, "dns_mx": False, "geoip": ""}]}


@pytest.fixture
def orch(monkeypatch, tmp_path):
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    # Lo store reale su una cartella temporanea: mai il volume /data.
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    return o


def _run(o, monkeypatch):
    posted = []

    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R(_FEED)
        if "/feed/whitelist" in url:
            return _R({"whitelist": {}})
        if url.startswith(o.TWIST_URL):
            return _R(_TWIST)
        return _R({})

    def _post(url, json=None, timeout=None, headers=None):
        posted.append(url)
        if url.endswith("/classify/variant"):
            return _R({"auto_classification": "needs_review", "confidence": "low", "rule": "no_matching_rule"})
        return _R({})

    monkeypatch.setattr(o._session, "get", _get)
    monkeypatch.setattr(o._session, "post", _post)
    o._run_pipeline(o.TriggerRequest(client="T-001", include_whois=False, include_reputation=False,
                                     include_dnstwist=True, variant_intel=True, scope="all"))
    return posted


def _written(tmp_path):
    return sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file())


class TestOPS06StoreDisabled:
    def test_no_snapshot_is_written_for_a_variant(self, orch, monkeypatch, tmp_path):
        _run(orch, monkeypatch)

        assert _written(tmp_path) == []

    def test_no_diff_or_history_for_a_variant_with_an_old_snapshot(self, orch, monkeypatch, tmp_path):
        assert orch.intel_store.save_snapshot("T-001", "acme-crop.example", {"dns": {"records": {"A": []}}})
        before = _written(tmp_path)

        posted = _run(orch, monkeypatch)

        assert not any(u.endswith("/diff") for u in posted)
        assert _written(tmp_path) == before

    def test_the_variant_is_still_classified_with_its_intel(self, orch, monkeypatch):
        posted = _run(orch, monkeypatch)

        assert sum(u.endswith("/classify/variant") for u in posted) == 2  # il dominio del feed e la variante


class TestOPS06StoreEnabled:
    def test_the_variant_snapshot_is_written(self, orch, monkeypatch, tmp_path):
        monkeypatch.setattr(orch, "INTEL_STORE", True)

        _run(orch, monkeypatch)

        assert "snapshots/t-001/acme-crop.example.json" in _written(tmp_path)
