"""SEC-14: il dominio entra codificato nelle URL verso i servizi interni.

L'orchestrator costruiva `.../dns?domain={domain}&full=true...` interpolando il dominio così com'era: un `&`, un `#`
o un `?` nel nome aggiungeva o toglieva parametri della chiamata interna, e restava solo il pattern dei servizi a
fermare un nome malformato. Ora il dominio è codificato: il servizio riceve esattamente il nome, e gli altri
parametri restano quelli dell'orchestrator.
"""

import importlib
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_orchestrator import _R

_ODD = "acme-crop.example&full=false&subdomains=false#frammento"


@pytest.fixture
def orch(monkeypatch):
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    return o


def _record_gets(o, monkeypatch, routes=None):
    urls = []

    def _get(url, timeout=None):
        urls.append(url)
        for prefix, payload in (routes or {}).items():
            if prefix in url:
                return _R(payload)
        return _R({})

    monkeypatch.setattr(o._session, "get", _get)
    return urls


def _query(url):
    parts = urlsplit(url)
    return parts.path, parts.fragment, parse_qs(parts.query, keep_blank_values=True)


class TestSEC14GatherIntelligence:
    def test_each_service_receives_exactly_the_domain_and_its_own_parameters(self, orch, monkeypatch):
        urls = _record_gets(orch, monkeypatch)

        orch._gather_intelligence(_ODD, orch.TriggerRequest(include_whois=True, include_reputation=True))

        got = {_query(u)[0]: _query(u)[1:] for u in urls}
        assert got == {
            "/dns": ("", {"domain": [_ODD], "full": ["true"], "subdomains": ["true"]}),
            "/cert": ("", {"domain": [_ODD]}),
            "/http": ("", {"domain": [_ODD]}),
            "/whois": ("", {"domain": [_ODD]}),
            "/reputation": ("", {"domain": [_ODD]}),
        }

    def test_an_ordinary_domain_gives_the_same_urls_as_before(self, orch, monkeypatch):
        urls = _record_gets(orch, monkeypatch)

        orch._gather_intelligence("acme-crop.example", orch.TriggerRequest(include_whois=True,
                                                                           include_reputation=True))

        assert sorted(urls) == sorted([
            f"{orch.DNS_URL}/dns?domain=acme-crop.example&full=true&subdomains=true",
            f"{orch.CERT_URL}/cert?domain=acme-crop.example",
            f"{orch.HTTP_URL}/http?domain=acme-crop.example",
            f"{orch.WHOIS_URL}/whois?domain=acme-crop.example",
            f"{orch.REP_URL}/reputation?domain=acme-crop.example",
        ])


class TestSEC14Dnstwist:
    def _pipeline(self, o, monkeypatch, legit, variants):
        feed = {"domains": [{"domain": "acme-corp.example", "client": "T-001", "type": "target", "legitimate": legit}]}
        urls = _record_gets(o, monkeypatch, {"/feed/domains": feed, "/feed/whitelist": {"whitelist": {}},
                                             "/twist": {"registered_variants": len(variants), "variants": variants}})
        monkeypatch.setattr(o._session, "post", lambda *a, **k: _R({}, ok=False, status_code=503))
        o._run_pipeline(o.TriggerRequest(client="T-001", include_whois=True, include_reputation=False,
                                         include_dnstwist=True, variant_intel=True, scope="all"))
        return urls

    def test_the_legitimate_domain_reaches_dnstwist_whole(self, orch, monkeypatch):
        urls = self._pipeline(orch, monkeypatch, _ODD, [])

        [twist] = [u for u in urls if urlsplit(u).path == "/twist"]
        assert _query(twist)[1:] == ("", {"domain": [_ODD]})

    def test_the_whois_only_lookup_of_a_homoglyph_gets_the_variant_whole(self, orch, monkeypatch):
        monkeypatch.setattr(orch, "WHOIS_ONLY_DOMAINS", {_ODD})
        monkeypatch.setattr(orch, "_cached_homoglyph_whois", lambda client, vdomain: None)
        variant = {"domain": _ODD, "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""}

        urls = self._pipeline(orch, monkeypatch, "acme-corp.example", [variant])

        [whois] = [u for u in urls if urlsplit(u).path == "/whois" and _ODD.split("&")[0] in u]
        assert _query(whois)[1:] == ("", {"domain": [_ODD]})
