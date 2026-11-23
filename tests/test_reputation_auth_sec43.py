"""SEC-43 + PERF-03 — `GET /reputation`: zona di fiducia e cache per dominio.

Autenticazione (decisione dell'utente):
  * con PIPELINE_TOKEN configurato nel servizio: serve `Authorization: Bearer <PIPELINE_TOKEN>`, altrimenti 401
    senza consumare quota VT (`_vt_call_times` invariato) e senza chiamare VT/OTX/SecurityTrails;
  * senza PIPELINE_TOKEN (assente o vuoto): resta aperta, con un WARNING all'avvio.
Cache (PERF-03): chiave `(domain, sources)`, TTL e dimensione massima da env; un secondo GET dentro il TTL non
chiama le fonti e non consuma quota; un esito con un errore in una fonte (anche VT_SKIPPED_ERROR e
REPUTATION_DEADLINE_ERROR) non si memorizza; fonti diverse = chiavi diverse.

Nomi assunti (da concordare col fixer; tutti letti all'import, quindi i test ricaricano il modulo):
  * env `PIPELINE_TOKEN`
  * env `REPUTATION_CACHE_TTL_S` (secondi, float; il default deve essere > 0 e piu' lungo della durata di un test)
  * env `REPUTATION_CACHE_MAX` (numero massimo di voci; oltre, si scarta la piu' vecchia)
  * attributi del modulo gia' esistenti: `REPUTATION_DEADLINE_S`, `VT_RATE_LIMIT`, `_vt_call_times`,
    `_vt_wait_for_slot`, `_check_otx`, `VT_SKIPPED_ERROR`, `REPUTATION_DEADLINE_ERROR`, `requests`.
"""
import importlib
import logging
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

PTOKEN = "test-pipeline-token-not-a-secret"
DOMAIN = "acme-typo.example"


class _Reply:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0, "undetected": 60,
                                                         "harmless": 10}, "reputation": -5, "categories": {}}}}
OTX_OK = {"pulse_info": {"count": 1, "pulses": [{"name": "p", "tags": ["t"], "malware_families": []}]}}
ST_OK = {"subdomain_count": 3, "current_dns": {}, "alexa_rank": 99}


class _Net:
    def __init__(self):
        self.calls = []          # (source, domain)
        self.replies = {"vt": _Reply(200, VT_OK), "otx": _Reply(200, OTX_OK), "st": _Reply(200, ST_OK)}

    def get(self, url, **kw):
        for host, key in (("virustotal", "vt"), ("alienvault", "otx"), ("securitytrails", "st")):
            if host in url:
                self.calls.append((key, url))
                return self.replies[key]
        raise AssertionError(f"GET non atteso: {url}")

    def count(self, key=None):
        return len([c for c in self.calls if key is None or c[0] == key])


def _load(monkeypatch, env=None, token=None):
    for k in ("PIPELINE_TOKEN", "REPUTATION_CACHE_TTL_S", "REPUTATION_CACHE_MAX"):
        monkeypatch.delenv(k, raising=False)
    if token is not None:
        monkeypatch.setenv("PIPELINE_TOKEN", token)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    import services.reputation as rep
    importlib.reload(rep)
    net = _Net()
    monkeypatch.setattr(rep, "VT_API_KEY", "vt-test-key")
    monkeypatch.setattr(rep, "OTX_API_KEY", "otx-test-key")
    monkeypatch.setattr(rep, "ST_API_KEY", "st-test-key")
    monkeypatch.setattr(rep, "VT_RATE_LIMIT", 100)
    monkeypatch.setattr(rep, "requests", SimpleNamespace(get=net.get))
    return rep, net, TestClient(rep.app)


@pytest.fixture
def load(monkeypatch):
    yield lambda env=None, token=None: _load(monkeypatch, env, token)
    monkeypatch.undo()
    import services.reputation as rep
    importlib.reload(rep)


def _get(c, domain=DOMAIN, sources="vt,otx,st", headers=None):
    return c.get("/reputation", params={"domain": domain, "sources": sources}, headers=headers or {})


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


class TestReputationAuth:
    def test_no_header_is_401_and_spends_nothing(self, load):
        rep, net, c = load(token=PTOKEN)
        before = list(rep._vt_call_times)
        r = _get(c)
        assert r.status_code == 401
        assert net.calls == []
        assert rep._vt_call_times == before

    def test_wrong_token_is_401_and_spends_nothing(self, load):
        rep, net, c = load(token=PTOKEN)
        r = _get(c, headers=_bearer("wrong-token"))
        assert r.status_code == 401
        assert net.calls == []
        assert rep._vt_call_times == []

    def test_non_bearer_scheme_is_401(self, load):
        rep, net, c = load(token=PTOKEN)
        r = _get(c, headers={"Authorization": f"Basic {PTOKEN}"})
        assert r.status_code == 401
        assert net.calls == []

    def test_valid_token_is_served(self, load):
        rep, net, c = load(token=PTOKEN)
        r = _get(c, headers=_bearer(PTOKEN))
        assert r.status_code == 200
        assert r.json()["virustotal"]["malicious"] == 2
        assert net.count() == 3

    def test_cached_result_is_not_served_to_unauthenticated_caller(self, load):
        rep, net, c = load(token=PTOKEN)
        assert _get(c, headers=_bearer(PTOKEN)).status_code == 200
        assert _get(c).status_code == 401

    @pytest.mark.parametrize("token", [None, ""])
    def test_open_when_token_not_configured(self, load, token):
        rep, net, c = load(token=token)
        assert _get(c).status_code == 200
        assert net.count() == 3

    def test_warning_at_startup_when_token_not_configured(self, monkeypatch, caplog, load):
        with caplog.at_level(logging.WARNING, logger="reputation"):
            load(token=None)
        assert any(r.levelno >= logging.WARNING and "PIPELINE_TOKEN" in r.getMessage() for r in caplog.records)

    def test_no_warning_when_token_configured(self, monkeypatch, caplog, load):
        with caplog.at_level(logging.WARNING, logger="reputation"):
            load(token=PTOKEN)
        assert not any("PIPELINE_TOKEN" in r.getMessage() for r in caplog.records)


class TestReputationCache:
    def test_second_get_within_ttl_calls_no_source_and_spends_no_quota(self, load):
        rep, net, c = load()
        first = _get(c)
        assert first.status_code == 200
        assert net.count() == 3
        quota = list(rep._vt_call_times)
        assert len(quota) == 1
        second = _get(c)
        assert second.status_code == 200
        assert net.count() == 3                # nessuna GET in piu'
        assert rep._vt_call_times == quota     # nessun posto VT in piu'
        assert second.json()["virustotal"] == first.json()["virustotal"]
        assert second.json()["risk_score"] == first.json()["risk_score"]

    def test_different_domain_is_a_different_entry(self, load):
        rep, net, c = load()
        _get(c, domain="one-typo.example")
        _get(c, domain="two-typo.example")
        assert net.count("vt") == 2

    def test_different_sources_are_different_keys(self, load):
        rep, net, c = load()
        _get(c, sources="vt")
        assert (net.count("vt"), net.count("otx"), net.count("st")) == (1, 0, 0)
        _get(c, sources="vt,otx,st")           # chiave diversa: non si serve dalla voce di "vt"
        assert (net.count("vt"), net.count("otx"), net.count("st")) == (2, 1, 1)
        _get(c, sources="vt")                  # e questa e' ancora in cache
        assert net.count("vt") == 2

    def test_entry_expires_after_ttl(self, load):
        rep, net, c = load(env={"REPUTATION_CACHE_TTL_S": "0.4"})
        _get(c)
        _get(c)
        assert net.count("vt") == 1
        time.sleep(0.6)
        _get(c)
        assert net.count("vt") == 2

    def test_cache_is_bounded_by_max_entries(self, load):
        rep, net, c = load(env={"REPUTATION_CACHE_MAX": "2"})
        for d in ("aa-typo.example", "bb-typo.example", "cc-typo.example"):
            _get(c, domain=d)
        assert net.count("vt") == 3
        _get(c, domain="aa-typo.example")      # la piu' vecchia e' stata scartata
        assert net.count("vt") == 4
        _get(c, domain="cc-typo.example")      # la piu' recente c'e' ancora
        assert net.count("vt") == 4

    @pytest.mark.parametrize("failing", ["vt", "otx", "st"])
    def test_outcome_with_a_source_error_is_not_cached(self, load, failing):
        rep, net, c = load()
        net.replies[failing] = _Reply(500)
        bad = _get(c).json()
        key = {"vt": "virustotal", "otx": "otx", "st": "securitytrails"}[failing]
        assert bad[key]["error"] == "HTTP 500"
        net.replies[failing] = _Reply(200, {"vt": VT_OK, "otx": OTX_OK, "st": ST_OK}[failing])
        good = _get(c).json()
        assert net.count(failing) == 2          # la seconda richiesta e' andata alla fonte
        assert good[key]["error"] is None

    def test_vt_skipped_outcome_is_not_cached(self, load, monkeypatch):
        rep, net, c = load()
        real = rep._vt_wait_for_slot
        state = {"n": 0}

        def wait():
            state["n"] += 1
            if state["n"] == 1:
                raise TimeoutError(rep.VT_SKIPPED_ERROR)
            return real()
        monkeypatch.setattr(rep, "_vt_wait_for_slot", wait)
        first = _get(c).json()
        assert first["virustotal"]["error"] == rep.VT_SKIPPED_ERROR
        second = _get(c).json()
        assert second["virustotal"]["error"] is None
        assert net.count("vt") == 1

    def test_deadline_outcome_is_not_cached(self, load, monkeypatch):
        rep, net, c = load()
        monkeypatch.setattr(rep, "REPUTATION_DEADLINE_S", 0.3)
        release = threading.Event()
        real_otx = rep._check_otx
        state = {"n": 0}

        def slow_then_fast(domain):
            state["n"] += 1
            if state["n"] == 1:
                release.wait(3)
                return rep._otx_empty()
            return real_otx(domain)
        monkeypatch.setattr(rep, "_check_otx", slow_then_fast)
        try:
            first = _get(c).json()
            assert first["otx"]["error"] == rep.REPUTATION_DEADLINE_ERROR
            second = _get(c).json()
            assert second["otx"]["error"] is None
            assert second["otx"]["pulse_count"] == 1
        finally:
            release.set()


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
# Giro 2: M1 (spazi nel token), M2 (lunghezza), L2 (chiave della cache, limite di `sources`, TTL=0)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
from shared.constants import VT_NOT_FOUND_ERROR


class TestReputationTokenWhitespaceM1:
    @pytest.mark.parametrize("header", ["Bearer    ", "Bearer   x", "Bearer"])
    def test_whitespace_only_token_authenticates_nobody(self, load, header):
        rep, net, c = load(token="   ")
        r = _get(c, headers={"Authorization": header})
        assert r.status_code == 401
        assert net.calls == []

    def test_outer_whitespace_in_env_is_ignored(self, load):
        rep, net, c = load(token=" " + PTOKEN + " ")
        assert _get(c, headers=_bearer(PTOKEN)).status_code == 200


class TestReputationLengthWarningM2:
    def test_short_token_warns_about_length(self, caplog, load):
        with caplog.at_level(logging.WARNING, logger="reputation"):
            load(token="short-test-token")
        msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("PIPELINE_TOKEN" in m and ("32" in m or "lungh" in m.lower() or "length" in m.lower())
                   for m in msgs), msgs

    def test_long_enough_token_does_not_warn(self, caplog, load):
        with caplog.at_level(logging.WARNING, logger="reputation"):
            load(token="t" * 40)
        assert not any("PIPELINE_TOKEN" in r.getMessage() for r in caplog.records)


class TestReputationCacheKeyL2:
    def test_domain_case_does_not_split_the_entry(self, load):
        rep, net, c = load()
        assert _get(c, domain="Acme-Typo.EXAMPLE").status_code == 200   # il pattern di `domain` accetta le maiuscole
        assert net.count("vt") == 1
        assert _get(c, domain="acme-typo.example").status_code == 200
        assert net.count("vt") == 1

    def test_unknown_source_shares_the_entry_of_the_known_ones(self, load):
        rep, net, c = load()
        _get(c, sources="vt,otx")
        assert (net.count("vt"), net.count("otx")) == (1, 1)
        _get(c, sources="vt,otx,bogus")
        assert (net.count("vt"), net.count("otx")) == (1, 1)

    def test_sources_of_64_chars_is_accepted(self, load):
        rep, net, c = load()
        s = ("vt," * 30)[:64]
        assert len(s) == 64
        assert _get(c, sources=s).status_code == 200

    def test_sources_longer_than_64_chars_is_422_and_spends_nothing(self, load):
        rep, net, c = load()
        s = ("vt," * 30)[:65]
        assert len(s) == 65
        r = _get(c, sources=s)
        assert r.status_code == 422
        assert net.calls == [] and rep._vt_call_times == []

    def test_vt_not_found_alone_is_cached(self, load):
        rep, net, c = load()
        net.replies["vt"] = _Reply(404)
        first = _get(c).json()
        assert first["virustotal"]["error"] == VT_NOT_FOUND_ERROR
        _get(c)
        assert net.count("vt") == 1 and net.count("otx") == 1 and net.count("st") == 1

    def test_vt_not_found_with_another_source_error_is_not_cached(self, load):
        rep, net, c = load()
        net.replies["vt"] = _Reply(404)
        net.replies["otx"] = _Reply(500)
        _get(c)
        _get(c)
        assert net.count("vt") == 2

    def test_ttl_zero_via_env_turns_the_cache_off(self, load):
        rep, net, c = load(env={"REPUTATION_CACHE_TTL_S": "0"})
        _get(c)
        _get(c)
        assert net.count("vt") == 2
