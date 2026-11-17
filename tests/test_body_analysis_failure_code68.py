"""CODE-68: un'analisi del corpo che fallisce resta sul suo URL e diventa un segnale, invece di abbassare il rischio.

Prima un'eccezione nell'analisi di una pagina usciva da `/http`: tutti e quattro i controlli andavano persi, la
sezione `http` arrivava vuota e il classificatore non vedeva più né il sito attivo né i tag nascosti (un dominio
giovane scendeva da HIGH a MEDIUM). Chi serve la pagina sceglie il markup, quindi il fallimento è una sua scelta.
Le due parti vanno insieme: con il solo isolamento il controllo fallito resterebbe un sito attivo con contenuto, e
la regola del contenuto sostanziale lo dichiarerebbe legittimo.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from services import http_fingerprint
from services.classifier import app as classifier_app

_DOMAIN = "acme-crop.example"
_TRIGGER = "PAGINA-CHE-FA-FALLIRE"
_NORMAL = "<html><title>Pagina</title><body>" + "contenuto ordinario " * 300 + "</body></html>"
_HIDDEN_FORM = '<form style="display:none" action="https://raccolta.example/p"></form>'


@pytest.fixture
def pages(monkeypatch):
    served = {}

    def _fetch(url, timeout=15, **kwargs):
        html = served.get(url)
        if html is None:
            return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                    "error": "connection refused", "attempts": 1}
        return {"status_code": 200, "content": html.encode(), "headers": {}, "final_url": url, "error": None,
                "attempts": 1}

    real_detect = http_fingerprint.detect_hidden_elements

    def _detect(html, self_domain=None):
        if _TRIGGER in html:
            raise RuntimeError("valore controllato da chi serve la pagina")
        return real_detect(html, self_domain=self_domain)

    monkeypatch.setattr(http_fingerprint, "http_get_with_retry", _fetch)
    monkeypatch.setattr(http_fingerprint, "detect_hidden_elements", _detect)
    return served


@pytest.fixture(scope="module")
def http_client():
    with TestClient(http_fingerprint.app) as client:
        yield client


def _checks(client):
    resp = client.get("/http", params={"domain": _DOMAIN, "check_www": True})
    assert resp.status_code == 200, resp.text[:300]
    return resp.json(), {c["url"]: c for c in resp.json()["checks"]}


class TestCODE68OneFailedAnalysisStaysOnItsUrl:
    def test_the_other_urls_keep_their_analysis(self, pages, http_client):
        pages[f"http://{_DOMAIN}"] = _NORMAL + _TRIGGER
        pages[f"https://{_DOMAIN}"] = _NORMAL + _HIDDEN_FORM

        result, checks = _checks(http_client)

        failed, other = checks[f"http://{_DOMAIN}"], checks[f"https://{_DOMAIN}"]
        assert failed["analysis_failed"] is True
        assert failed["hidden_elements"] is None
        assert other["hidden_elements"]["hidden_forms"]
        assert "analysis_failed" not in other
        assert result["overall_status"] == "active"
        assert result["hidden_elements_risk"] == 30

    def test_a_failure_is_logged_with_the_url_and_the_class_only(self, pages, http_client, caplog):
        pages[f"http://{_DOMAIN}"] = _NORMAL + _TRIGGER

        with caplog.at_level(logging.WARNING, logger="http-fp"):
            _checks(http_client)

        lines = [r.getMessage() for r in caplog.records if r.name == "http-fp" and r.levelno == logging.WARNING]
        assert any(f"http://{_DOMAIN}" in line and "RuntimeError" in line for line in lines), lines
        assert not any("valore controllato" in line for line in lines)

    def test_the_analysis_turn_is_free_after_a_failure(self, pages, http_client):
        pages[f"http://{_DOMAIN}"] = _NORMAL + _TRIGGER
        _checks(http_client)
        pages[f"http://{_DOMAIN}"] = _NORMAL + _HIDDEN_FORM

        _, checks = _checks(http_client)

        assert checks[f"http://{_DOMAIN}"]["hidden_elements"]["hidden_forms"]


_classifier = TestClient(classifier_app)
_OLD_WHOIS = {"domain": _DOMAIN, "creation_date": "2003-09-17T10:21:05", "updated_date": "2010-01-01T00:00:00"}


def _classify(checks, whois=None):
    resp = _classifier.post("/classify/variant", json={
        "domain": _DOMAIN, "fuzzer": "transposition",
        "dns": {"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.example.net"]}},
        "http": {"checks": checks, "overall_status": "active"}, "whois": whois})
    assert resp.status_code == 200, resp.text
    r = resp.json()
    return r["auto_classification"], r["confidence"], r["rule"]


class TestCODE68TheClassifierReadsTheFailure:
    def test_a_failed_analysis_on_a_substantial_page_is_not_legitimate(self):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 6000, "analysis_failed": True}]

        assert _classify(checks) == ("suspicious", "high", "body_analysis_failed")

    def test_a_failed_analysis_on_a_tiny_page_is_not_parking(self):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 40, "analysis_failed": True}]

        assert _classify(checks)[0] == "suspicious"

    def test_it_wins_over_a_clean_analysis_of_another_url(self):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 6000, "analysis_failed": True},
                  {"url": f"https://{_DOMAIN}", "status_code": 200, "content_length": 6000,
                   "hidden_elements": {"risk_indicators": 0, "summary": []}}]

        assert _classify(checks)[2] == "body_analysis_failed"

    def test_on_an_old_domain_it_asks_for_review(self):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 6000, "analysis_failed": True}]

        assert _classify(checks, whois=_OLD_WHOIS) == ("needs_review", "medium", "body_analysis_failed_aged_domain")

    def test_without_a_failure_nothing_changes(self):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 6000,
                   "hidden_elements": {"risk_indicators": 0, "summary": []}}]

        assert _classify(checks) == ("legitimate_probable", "low", "http_active_substantial_content")


class TestCODE68IsolationAlsoCoversTheDownload:
    def test_a_download_that_raises_is_one_unreached_url(self, pages, http_client, monkeypatch):
        pages[f"https://{_DOMAIN}"] = _NORMAL + _HIDDEN_FORM
        served = http_fingerprint.http_get_with_retry

        def _fetch(url, timeout=15, **kwargs):
            if url == f"http://{_DOMAIN}":
                raise ConnectionError("dettaglio della rete")
            return served(url, timeout=timeout, **kwargs)

        monkeypatch.setattr(http_fingerprint, "http_get_with_retry", _fetch)

        result, checks = _checks(http_client)

        assert checks[f"http://{_DOMAIN}"]["status_code"] is None
        assert checks[f"http://{_DOMAIN}"]["error"] == "fetch failed"
        assert "analysis_failed" not in checks[f"http://{_DOMAIN}"]
        assert checks[f"https://{_DOMAIN}"]["hidden_elements"]["hidden_forms"]
        assert result["overall_status"] == "active"

    def test_a_hash_that_raises_is_an_analysis_failure(self, pages, http_client, monkeypatch):
        pages[f"http://{_DOMAIN}"] = _NORMAL + _TRIGGER
        real_hash = http_fingerprint.content_hash
        monkeypatch.setattr(http_fingerprint, "content_hash",
                            lambda c: (_ for _ in ()).throw(ValueError("x")) if _TRIGGER in c else real_hash(c))

        _, checks = _checks(http_client)

        assert checks[f"http://{_DOMAIN}"]["analysis_failed"] is True

    def test_memory_exhaustion_is_not_a_signal_about_the_page(self, pages, monkeypatch):
        pages[f"http://{_DOMAIN}"] = _NORMAL
        monkeypatch.setattr(http_fingerprint, "detect_hidden_elements",
                            lambda html, self_domain=None: (_ for _ in ()).throw(MemoryError()))

        with TestClient(http_fingerprint.app, raise_server_exceptions=False) as client:
            resp = client.get("/http", params={"domain": _DOMAIN, "check_www": False})

        assert resp.status_code == 500


class TestCODE68OnlyABooleanCounts:
    @pytest.mark.parametrize("value", ["false", "true", 1, None])
    def test_a_flag_that_is_not_true_is_not_read(self, value):
        checks = [{"url": f"http://{_DOMAIN}", "status_code": 200, "content_length": 6000, "analysis_failed": value,
                   "hidden_elements": {"risk_indicators": 0, "summary": []}}]

        assert _classify(checks)[2] == "http_active_substantial_content"


def _diff(domain, legitimate, prev_checks, curr_checks):
    resp = _classifier.post("/diff", json={
        "domain": domain, "client": "T-001", "legitimate": legitimate,
        "baseline": {"http": {"checks": prev_checks}}, "current": {"http": {"checks": curr_checks}}})
    assert resp.status_code == 200, resp.text
    return [(a["type"], a["severity"]) for a in resp.json()["alerts"]
            if a["type"].endswith("body_analysis_failed")]


_OK = {"url": "https://acme-corp.example", "status_code": 200, "content_length": 6000,
       "hidden_elements": {"risk_indicators": 0, "summary": []}}
_FAILED = {"url": "https://acme-corp.example", "status_code": 200, "content_length": 6000, "analysis_failed": True}


class TestCODE68AlertChannel:
    def test_on_the_legitimate_domain_a_new_failure_raises_an_alert(self):
        assert _diff("acme-corp.example", "acme-corp.example", [_OK], [_FAILED]) \
            == [("legit_body_analysis_failed", "HIGH")]

    def test_on_a_variant_a_new_failure_raises_an_alert(self):
        assert _diff("acme-crop.example", "acme-corp.example", [_OK], [_FAILED]) == [("body_analysis_failed", "HIGH")]

    def test_on_the_legitimate_domain_the_alert_repeats_while_the_failure_lasts(self):
        assert _diff("acme-corp.example", "acme-corp.example", [_FAILED], [_FAILED]) \
            == [("legit_body_analysis_failed", "HIGH")]

    def test_on_a_variant_a_failure_already_in_the_baseline_is_not_repeated(self):
        assert _diff("acme-crop.example", "acme-corp.example", [_FAILED], [_FAILED]) == []

    def test_a_flag_that_is_not_true_raises_nothing(self):
        assert _diff("acme-corp.example", "acme-corp.example", [_OK], [{**_FAILED, "analysis_failed": "true"}]) == []
