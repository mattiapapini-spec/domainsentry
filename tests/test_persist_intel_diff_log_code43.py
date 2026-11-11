"""CODE-43: un `/diff` che risponde con un errore HTTP lascia una riga di log.

`_persist_intel` loggava solo le eccezioni della chiamata: con una risposta 500 il confronto col ciclo precedente si
perdeva senza traccia, e lo snapshot veniva sovrascritto lo stesso (questa parte resta a `COL-29`).
"""

import importlib
import logging

import pytest

from tests.test_orchestrator import _R

_PREV = {"dns": {"records": {"A": ["192.0.2.1"]}}}
_CURR = {"dns": {"records": {"A": ["192.0.2.2"]}}}


@pytest.fixture
def orch(monkeypatch, tmp_path):
    monkeypatch.setenv("INTEL_STORE", "true")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    # Lo store reale su una cartella temporanea: mai il volume /data.
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    assert o.intel_store.save_snapshot("T-001", "acme-crop.example", _PREV)
    return o


def _persist(o, monkeypatch, caplog, answer):
    monkeypatch.setattr(o._session, "post", lambda url, json=None, timeout=None: answer)
    with caplog.at_level(logging.WARNING, logger="orchestrator"):
        o._persist_intel("T-001", "acme-crop.example", "acme-corp.example", _CURR)
    return [r.getMessage() for r in caplog.records if r.name == "orchestrator" and r.levelno >= logging.WARNING]


class TestCODE43DiffErrorIsLogged:
    @pytest.mark.parametrize("status", [500, 502, 422])
    def test_an_error_answer_leaves_a_warning_with_domain_and_status(self, orch, monkeypatch, caplog, status):
        warnings = _persist(orch, monkeypatch, caplog, _R({"detail": "errore"}, ok=False, status_code=status))

        assert [w for w in warnings if "diff" in w and f"HTTP {status}" in w and "acme-crop.example" in w]

    def test_a_good_answer_logs_no_warning(self, orch, monkeypatch, caplog):
        warnings = _persist(orch, monkeypatch, caplog, _R({"alert_count": 0, "alerts": []}))

        assert not [w for w in warnings if "diff" in w]

    def test_the_snapshot_is_still_saved_as_before(self, orch, monkeypatch, caplog):
        _persist(orch, monkeypatch, caplog, _R({}, ok=False, status_code=500))

        assert orch.intel_store.load_snapshot("T-001", "acme-crop.example")["intel"]["dns"]["records"]["A"] \
            == ["192.0.2.2"]
