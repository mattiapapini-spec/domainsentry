"""CODE-17: una variante scoperta da dnstwist passa dal classificatore anche quando non si raccoglie la sua intel.

Prima, senza `variant_intel` (o per una variante che non risolve e non è un omografo) l'evento portava il segnaposto
fisso `needs_review`/`dnstwist_discovery` e il classificatore non veniva mai consultato: le regole sul solo nome,
come la mescolanza di script di un omografo, non valevano per queste varianti. Ora il classificatore riceve il nome
e il fuzzer, senza moduli dichiarati: nessun dato mancante viene letto come assente.
"""

import importlib

import pytest

from tests.test_orchestrator import (AGED_HOMOGLYPH_SNAPSHOT_INTEL, _R, _event_for, _real_classifier_post,
                                    _severity_of)


@pytest.fixture
def orch(monkeypatch):
    # Come in tests/test_orchestrator.py: intel store e ingest dei casi spenti.
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    return o

_FEED = {"domains": [{"domain": "acme-corp.example", "client": "T-001", "type": "target",
                      "legitimate": "acme-corp.example"}]}
_HOMOGLYPH = "аcme-corp.example"  # `а` cirillica al posto della `a` latina
_TWIST = {"registered_variants": 2, "variants": [
    {"domain": _HOMOGLYPH, "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""},
    {"domain": "acme-crop.example", "fuzzer": "transposition", "dns_a": False, "dns_mx": False, "geoip": ""},
]}


def _run(o, monkeypatch, variant_intel, post=None):
    published, classify_payloads = [], []

    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R(_FEED)
        if "/feed/whitelist" in url:
            return _R({"whitelist": {}})
        if url.startswith(o.TWIST_URL):
            return _R(_TWIST)
        return _R({})

    monkeypatch.setattr(o._session, "get", _get)
    monkeypatch.setattr(o._session, "post", post or _real_classifier_post(o, published, classify_payloads))
    o._run_pipeline(o.TriggerRequest(client="T-001", include_whois=False, include_reputation=False,
                                     include_dnstwist=True, variant_intel=variant_intel, scope="all"))
    return published, classify_payloads


def _classified(payloads):
    return {p["domain"]: p for p in payloads if p["domain"] != "acme-corp.example"}


class TestCODE17WithoutVariantIntel:
    def test_every_discovered_variant_goes_through_the_classifier(self, orch, monkeypatch):
        _, payloads = _run(orch, monkeypatch, variant_intel=False)

        assert set(_classified(payloads)) == {_HOMOGLYPH, "acme-crop.example"}

    def test_only_the_name_is_sent_and_no_module_is_declared(self, orch, monkeypatch):
        _, payloads = _run(orch, monkeypatch, variant_intel=False)

        sent = _classified(payloads)["acme-crop.example"]
        assert sent == {"domain": "acme-crop.example", "fuzzer": "transposition", "whois": None,
                        "collection_status": {}}

    def test_a_homoglyph_gets_the_classification_of_its_name(self, orch, monkeypatch):
        published, _ = _run(orch, monkeypatch, variant_intel=False)

        ev = _event_for(published, _HOMOGLYPH)
        assert ev["classification"]["auto_classification"] == "suspicious"
        assert _severity_of(orch, ev) == "HIGH"

    def test_a_variant_with_no_rule_keeps_needs_review_from_the_classifier(self, orch, monkeypatch):
        published, _ = _run(orch, monkeypatch, variant_intel=False)

        cls = _event_for(published, "acme-crop.example")["classification"]
        assert cls["auto_classification"] == "needs_review"
        assert cls["rule"] != "dnstwist_discovery"


    def test_a_homoglyph_with_a_known_old_whois_is_not_raised_to_high(self, orch, monkeypatch, tmp_path):
        # Il WHOIS già osservato in un ciclo precedente (SCO-05), dalla cache in-process: `intel_store` non accetta
        # nomi Unicode come nome di file. Lo store punta comunque a una cartella temporanea, mai al volume /data.
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
        orch._remember_homoglyph_whois("T-001", _HOMOGLYPH, AGED_HOMOGLYPH_SNAPSHOT_INTEL["whois"])

        published, payloads = _run(orch, monkeypatch, variant_intel=False)

        assert _classified(payloads)[_HOMOGLYPH]["whois"] == AGED_HOMOGLYPH_SNAPSHOT_INTEL["whois"]
        assert _severity_of(orch, _event_for(published, _HOMOGLYPH)) == "LOW"


class TestCODE17WithVariantIntel:
    def test_a_variant_that_does_not_resolve_goes_through_the_classifier(self, orch, monkeypatch):
        _, payloads = _run(orch, monkeypatch, variant_intel=True)

        assert "acme-crop.example" in _classified(payloads)


class TestCODE17WhenTheClassifierFails:
    def test_the_placeholder_stays_and_the_event_is_published(self, orch, monkeypatch):
        published = []

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/classify/variant"):
                if json["domain"] == "acme-corp.example":
                    return _R({"auto_classification": "needs_review", "confidence": "low"})
                raise ConnectionError("classificatore giù")
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
            return _R({})

        _run(orch, monkeypatch, variant_intel=False, post=_post)

        cls = _event_for(published, "acme-crop.example")["classification"]
        assert (cls["auto_classification"], cls["rule"]) == ("needs_review", "dnstwist_discovery")

    def test_a_non_ok_answer_keeps_the_placeholder(self, orch, monkeypatch):
        published = []

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/classify/variant"):
                return _R({"detail": "errore"}, ok=False, status_code=500)
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
            return _R({})

        _run(orch, monkeypatch, variant_intel=False, post=_post)

        cls = _event_for(published, _HOMOGLYPH)["classification"]
        assert (cls["auto_classification"], cls["rule"]) == ("needs_review", "dnstwist_discovery")
