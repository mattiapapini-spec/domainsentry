"""CODE-71: una risposta di errore di un servizio di intelligence lascia una riga di log.

`_fetch_service` restituiva `None` («nessun dato») per qualunque risposta non ok, senza log: un 500 di `/http`
(per esempio un'analisi che falliva, `CODE-68`) era indistinguibile da un servizio che non aveva nulla da dire. Le
eccezioni erano già loggate.
"""

import importlib
import logging

import pytest

from tests.test_orchestrator import _R


@pytest.fixture
def orch(monkeypatch):
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    return o


def _fetch(o, monkeypatch, caplog, answer, name="http"):
    monkeypatch.setattr(o._session, "get", lambda url, timeout=None: answer)
    with caplog.at_level(logging.WARNING, logger="orchestrator"):
        got = o._fetch_service(name, f"{o.HTTP_URL}/http?domain=acme-crop.example")
    lines = [r.getMessage() for r in caplog.records if r.name == "orchestrator" and r.levelno >= logging.WARNING]
    return got, lines


class TestCODE71ServiceErrorIsLogged:
    @pytest.mark.parametrize("status", [500, 503, 422, 404])
    def test_an_error_answer_is_still_no_data_but_leaves_a_warning(self, orch, monkeypatch, caplog, status):
        got, lines = _fetch(orch, monkeypatch, caplog, _R({"detail": "x"}, ok=False, status_code=status))

        assert got == ("http", None)
        assert [line for line in lines if "http" in line and f"HTTP {status}" in line
                and "acme-crop.example" in line], lines

    def test_the_service_name_is_in_the_line(self, orch, monkeypatch, caplog):
        _, lines = _fetch(orch, monkeypatch, caplog, _R({}, ok=False, status_code=500), name="whois")

        assert any(line.strip().startswith("whois") for line in lines), lines

    def test_a_good_answer_logs_nothing(self, orch, monkeypatch, caplog):
        got, lines = _fetch(orch, monkeypatch, caplog, _R({"checks": []}))

        assert got == ("http", {"checks": []})
        assert lines == []
