"""COL-29: l'orchestrator non perde più in silenzio i risultati quando classificazione, diff, pubblicazione o discovery
falliscono (variante A, scelta di Mat).

Prima: con la classificazione fallita il dominio spariva dagli eventi; con un `/diff` fallito lo snapshot veniva
sovrascritto e la variazione di quel ciclo non usciva mai; «Pubblicati N eventi» compariva anche quando `/publish`
rispondeva con un errore; un dnstwist in errore HTTP non lasciava traccia; la fase finiva «done» senza dire nulla.
Ora:

* classificazione fallita: l'evento esce lo stesso con una classificazione di ripiego `needs_review` e regola
  `classification_unavailable`, che non passa dai casi (riscriverebbe la classificazione dei casi aperti);
* `/diff` fallito, o storia non scritta: lo snapshot si aggiorna comunque (COL-16), ma conserva la baseline
  dell'ultimo diff riuscito; il diff del ciclo dopo parte da lì e la variazione esce allora;
* pubblicazione e dnstwist falliti: una riga di log;
* ogni fallimento è contato in `/progress` (`failures`).
"""

import importlib
import logging

import pytest

from tests.test_orchestrator import _R

_DOMAIN = "acme-crop.example"
_FEED = {"domains": [{"domain": _DOMAIN, "client": "T-001", "type": "target", "legitimate": "acme-corp.example"}]}
_OLD = {"dns": {"records": {"A": ["192.0.2.1"]}, "records_status": {"A": "ok"}}}
_CLASSIFIED = {"auto_classification": "suspicious", "confidence": "high", "rule": "mx_only_no_web", "rationale": "x"}


@pytest.fixture
def orch(monkeypatch, tmp_path):
    monkeypatch.setenv("INTEL_STORE", "true")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    # Lo store reale su una cartella temporanea: mai il volume /data.
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    return o


def _run(o, monkeypatch, classify=None, diff=None, publish=None, twist=None):
    calls = {"published": [], "ingested": [], "diff": []}

    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R(_FEED)
        if "/feed/whitelist" in url:
            return _R({"whitelist": {}})
        if url.startswith(o.TWIST_URL):
            return twist or _R({"registered_variants": 0, "variants": []})
        if url.startswith(o.DNS_URL + "/dns"):
            return _R({"records": {"A": ["192.0.2.2"]}, "records_status": {"A": "ok"}})
        return _R({})

    def _post(url, json=None, timeout=None, headers=None):
        if url.endswith("/classify/variant"):
            if isinstance(classify, Exception):
                raise classify
            return classify or _R(_CLASSIFIED)
        if url.endswith("/diff"):
            calls["diff"].append(json)
            if isinstance(diff, Exception):
                raise diff
            return diff or _R({"alert_count": 1, "alerts": [{"type": "a_record_changed"}], "max_severity": "HIGH"})
        if url.endswith("/publish"):
            calls["published"].extend((json or {}).get("events", []))
            return publish or _R({})
        if url.endswith("/cases/ingest"):
            calls["ingested"].append(json)
            return _R({})
        return _R({})

    monkeypatch.setattr(o._session, "get", _get)
    monkeypatch.setattr(o._session, "post", _post)
    o._run_pipeline(o.TriggerRequest(client="T-001", include_whois=False, include_reputation=False,
                                     include_dnstwist=twist is not None, scope="all"))
    state = o.progress(include_log=True)
    return calls, state


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "orchestrator" and r.levelno >= logging.WARNING]


class TestCOL29FailedClassification:
    @pytest.mark.parametrize("answer", [_R({"detail": "x"}, ok=False, status_code=500), ConnectionError("giù")])
    def test_the_domain_still_reaches_the_events_marked_as_unclassified(self, orch, monkeypatch, caplog, answer):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            calls, state = _run(orch, monkeypatch, classify=answer)

        [event] = calls["published"]
        assert event["domain"] == _DOMAIN
        assert (event["classification"]["auto_classification"], event["classification"]["rule"]) \
            == ("needs_review", "classification_unavailable")
        assert state["failures"]["classification"] == 1
        assert any(_DOMAIN in w and "classif" in w.lower() for w in _warnings(caplog)), _warnings(caplog)

    def test_an_unclassified_event_does_not_touch_the_cases(self, orch, monkeypatch):
        monkeypatch.setattr(orch, "CASE_INGEST", True)
        monkeypatch.setattr(orch, "CASE_INGEST_TOKEN", "token-di-prova")

        calls, _ = _run(orch, monkeypatch, classify=_R({}, ok=False, status_code=503))

        assert calls["published"] and calls["ingested"] == []

    def test_a_classified_event_still_reaches_the_cases(self, orch, monkeypatch):
        monkeypatch.setattr(orch, "CASE_INGEST", True)
        monkeypatch.setattr(orch, "CASE_INGEST_TOKEN", "token-di-prova")

        calls, state = _run(orch, monkeypatch)

        assert [c["classification"] for c in calls["ingested"]] == ["suspicious"]
        assert state["failures"] == {"classification": 0, "diff": 0, "publish": 0, "discovery": 0}


class TestCOL29FailedDiffKeepsTheBaseline:
    def _record(self, o):
        return o.intel_store.load_snapshot("T-001", _DOMAIN) or {}

    def _records(self, o):
        return self._record(o).get("intel", {}).get("dns", {}).get("records")

    def _pending(self, o):
        return (self._record(o).get("diff_baseline") or {}).get("dns", {}).get("records")

    @pytest.mark.parametrize("answer", [_R({}, ok=False, status_code=500), ConnectionError("giù")])
    def test_a_failed_diff_updates_the_snapshot_and_keeps_the_last_good_baseline(self, orch, monkeypatch, caplog,
                                                                                 answer):
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)

        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            _, state = _run(orch, monkeypatch, diff=answer)

        assert self._records(orch) == {"A": ["192.0.2.2"]}
        assert self._pending(orch) == {"A": ["192.0.2.1"]}
        assert state["failures"]["diff"] == 1
        assert any("baseline" in w for w in _warnings(caplog)), _warnings(caplog)

    def test_the_change_comes_out_at_the_next_cycle(self, orch, monkeypatch):
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)
        _run(orch, monkeypatch, diff=_R({}, ok=False, status_code=500))

        calls, state = _run(orch, monkeypatch)

        assert calls["diff"][0]["baseline"]["dns"]["records"] == {"A": ["192.0.2.1"]}
        assert self._records(orch) == {"A": ["192.0.2.2"]} and "diff_baseline" not in self._record(orch)
        assert state["failures"]["diff"] == 0

    def test_two_failures_in_a_row_keep_the_oldest_good_baseline(self, orch, monkeypatch):
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)
        _run(orch, monkeypatch, diff=_R({}, ok=False, status_code=500))
        _run(orch, monkeypatch, diff=_R({}, ok=False, status_code=500))

        assert self._pending(orch) == {"A": ["192.0.2.1"]}

    def test_a_history_that_cannot_be_written_keeps_the_baseline(self, orch, monkeypatch):
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)
        monkeypatch.setattr(orch.intel_store, "append_history", lambda client, domain, diff: False)

        _, state = _run(orch, monkeypatch)

        assert self._pending(orch) == {"A": ["192.0.2.1"]}
        assert state["failures"]["diff"] == 1

    def test_a_diff_with_no_change_is_not_a_failure(self, orch, monkeypatch):
        # `append_history` restituisce False anche quando non c'è nulla da scrivere: non è un guasto.
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)

        _, state = _run(orch, monkeypatch, diff=_R({"alert_count": 0, "alerts": [], "max_severity": "CLEAN"}))

        assert self._records(orch) == {"A": ["192.0.2.2"]} and "diff_baseline" not in self._record(orch)
        assert state["failures"]["diff"] == 0

    def test_without_a_previous_snapshot_the_first_one_is_saved(self, orch, monkeypatch):
        _, state = _run(orch, monkeypatch, diff=_R({}, ok=False, status_code=500))

        assert self._records(orch) == {"A": ["192.0.2.2"]}
        assert state["failures"]["diff"] == 0

    def test_the_intelligence_view_does_not_show_the_pending_baseline(self, orch, monkeypatch):
        assert orch.intel_store.save_snapshot("T-001", _DOMAIN, _OLD)
        _run(orch, monkeypatch, diff=_R({}, ok=False, status_code=500))

        assert "diff_baseline" not in orch.intel_store.get_intel("T-001", _DOMAIN)["snapshot"]


class TestCOL29PublishAndDiscovery:
    def test_a_failed_publish_is_not_reported_as_published(self, orch, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            _, state = _run(orch, monkeypatch, publish=_R({}, ok=False, status_code=500))

        assert not any("Pubblicati" in line["msg"] for line in state["log"]), state["log"]
        assert state["failures"]["publish"] == 1
        assert any("publish" in w.lower() and "500" in w for w in _warnings(caplog)), _warnings(caplog)

    def test_a_good_publish_is_reported(self, orch, monkeypatch):
        _, state = _run(orch, monkeypatch)

        assert any("Pubblicati 1 eventi" in line["msg"] for line in state["log"]), state["log"]
        assert state["failures"]["publish"] == 0

    def test_a_failed_discovery_is_logged_and_counted(self, orch, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            _, state = _run(orch, monkeypatch, twist=_R({}, ok=False, status_code=502))

        assert state["failures"]["discovery"] == 1
        assert any("acme-corp.example" in w and "502" in w for w in _warnings(caplog)), _warnings(caplog)

    def test_a_new_run_starts_from_zero(self, orch, monkeypatch):
        _run(orch, monkeypatch, publish=_R({}, ok=False, status_code=500))

        _, state = _run(orch, monkeypatch)

        assert state["failures"] == {"classification": 0, "diff": 0, "publish": 0, "discovery": 0}
