"""PERF-07 — `POST /trigger` e `POST /trigger/reset` dell'orchestrator richiedono autenticazione.

Decisione dell'utente. Due chiamanti ammessi:
  (a) `Authorization: Bearer <PIPELINE_TOKEN>`: variabile d'ambiente nuova, separata da SERVICE_TOKEN;
      un PIPELINE_TOKEN vuoto o assente non autentica nessuno;
  (b) `Authorization: Bearer <token di sessione>` verificato dal case-manager (`verify_token_remote`),
      con permesso `manage_cases` (admin e analyst si', viewer no). L'identita' di servizio del
      case-manager (ruolo `service`, utente `svc-orchestrator`, che ha `manage_cases`) NON puo' avviare scansioni.
Fail-closed: senza header, token sbagliato, case-manager giu' -> 401; utente senza permesso -> 403.
La pipeline non parte, `_running` non cambia, e un reset rifiutato non sblocca nulla.
Il punto 4 della decisione: l'orchestrator manda il PIPELINE_TOKEN solo a `/reputation`.

Assunzioni sui nomi (da `services.orchestrator`):
  * env `PIPELINE_TOKEN`, letta all'import (i test ricaricano il modulo);
  * `verify_token_remote` raggiungibile come attributo del modulo (come in feed_manager) oppure come
    `shared.auth.verify_token_remote` chiamata attraverso il modulo: i test sostituiscono entrambi;
  * `_run_pipeline`, `_running`, `_last_heartbeat`, `_run_started`, `_session`, `_gather_intelligence`.
"""
import importlib
import logging
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

PTOKEN = "test-pipeline-token-not-a-secret"
SESSION = "test-session-token-not-a-secret"

ADMIN = {"id": 1, "username": "admin-test", "role": "admin",
         "permissions": ["manage_users", "assign_cases", "manage_cases", "whitelist", "add_notes", "view"]}
ANALYST = {"id": 2, "username": "analyst-test", "role": "analyst",
           "permissions": ["assign_cases", "manage_cases", "whitelist", "add_notes", "view"]}
VIEWER = {"id": 3, "username": "viewer-test", "role": "viewer", "permissions": ["view"]}
SERVICE = {"id": 0, "username": "svc-orchestrator", "role": "service", "permissions": ["manage_cases", "view"]}


def _load(monkeypatch, pipeline_token):
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    monkeypatch.setenv("CASE_MANAGER_URL", "http://case-manager.example:8012")
    if pipeline_token is None:
        monkeypatch.delenv("PIPELINE_TOKEN", raising=False)
    else:
        monkeypatch.setenv("PIPELINE_TOKEN", pipeline_token)
    import services.orchestrator as o
    importlib.reload(o)
    return o


@pytest.fixture
def make_orch(monkeypatch):
    """`make(pipeline_token)` ricarica l'orchestrator con quel PIPELINE_TOKEN; a fine prova lo ripristina."""
    def make(pipeline_token=PTOKEN):
        o = _load(monkeypatch, pipeline_token)
        started = []
        monkeypatch.setattr(o, "_run_pipeline", lambda req: started.append(req))
        o._running = False
        return o, TestClient(o.app), started
    yield make
    monkeypatch.undo()
    import services.orchestrator as o
    importlib.reload(o)


def _remote(monkeypatch, o, user):
    """Il case-manager finto: ritorna `user` (o None = giu'/token non valido) e registra le chiamate."""
    calls = []

    def fake(token, url=None, *a, **kw):
        calls.append((token, url))
        return user
    monkeypatch.setattr(o, "verify_token_remote", fake, raising=False)
    import shared.auth
    monkeypatch.setattr(shared.auth, "verify_token_remote", fake)
    return calls


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


class TestTriggerRejects:
    def test_no_header_is_401_and_pipeline_does_not_start(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        r = c.post("/trigger", json={"client": "T-001"})
        assert r.status_code == 401
        assert started == []
        assert o._running is False

    def test_wrong_token_is_401(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        r = c.post("/trigger", json={}, headers=_bearer("wrong-token"))
        assert r.status_code == 401
        assert started == [] and o._running is False

    def test_non_bearer_scheme_is_401(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        r = c.post("/trigger", json={}, headers={"Authorization": f"Basic {PTOKEN}"})
        assert r.status_code == 401
        assert started == []

    @pytest.mark.parametrize("configured", [None, ""])
    def test_empty_or_missing_pipeline_token_authenticates_nobody(self, make_orch, monkeypatch, configured):
        o, c, started = make_orch(configured)
        _remote(monkeypatch, o, None)
        for headers in ({"Authorization": "Bearer "}, {"Authorization": "Bearer"}, _bearer("x"), {}):
            r = c.post("/trigger", json={}, headers=headers)
            assert r.status_code == 401, headers
        assert started == [] and o._running is False

    def test_viewer_is_403(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, VIEWER)
        r = c.post("/trigger", json={}, headers=_bearer(SESSION))
        assert r.status_code == 403
        assert started == [] and o._running is False

    def test_service_identity_cannot_start_scans(self, make_orch, monkeypatch):
        """SERVICE_TOKEN (svc-orchestrator, ha manage_cases) non va allargato a /trigger."""
        o, c, started = make_orch()
        _remote(monkeypatch, o, SERVICE)
        r = c.post("/trigger", json={}, headers=_bearer(SESSION))
        assert r.status_code in (401, 403)
        assert started == [] and o._running is False

    def test_case_manager_down_without_valid_pipeline_token_is_401(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)  # verify_token_remote ritorna None se irraggiungibile
        r = c.post("/trigger", json={}, headers=_bearer(SESSION))
        assert r.status_code == 401
        assert started == [] and o._running is False

    def test_rejected_call_does_not_run_stale_recovery(self, make_orch, monkeypatch):
        """Una richiesta non autenticata non deve nemmeno toccare il lucchetto (reset forzato dello stale)."""
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - (o.HEARTBEAT_STALE_SEC + 60)
        r = c.post("/trigger", json={})
        assert r.status_code == 401
        assert o._running is True
        assert started == []

    def test_rejected_call_on_running_pipeline_is_401_not_409(self, make_orch, monkeypatch):
        """L'autenticazione precede il controllo di stato: niente informazione su `running_since` a chi non e' autenticato."""
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - 30
        r = c.post("/trigger", json={})
        assert r.status_code == 401
        assert "running_since" not in r.text


class TestTriggerAccepts:
    def test_pipeline_token_starts_pipeline(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        r = c.post("/trigger", json={"client": "T-001"}, headers=_bearer(PTOKEN))
        assert r.status_code == 200
        assert r.json()["status"] == "triggered"
        assert len(started) == 1

    @pytest.mark.parametrize("user", [ADMIN, ANALYST], ids=["admin", "analyst"])
    def test_session_of_user_with_manage_cases_starts_pipeline(self, make_orch, monkeypatch, user):
        o, c, started = make_orch()
        calls = _remote(monkeypatch, o, user)
        r = c.post("/trigger", json={}, headers=_bearer(SESSION))
        assert r.status_code == 200
        assert len(started) == 1
        assert calls and calls[0][0] == SESSION
        assert calls[0][1] == "http://case-manager.example:8012"

    def test_pipeline_token_works_with_case_manager_down(self, make_orch, monkeypatch):
        o, c, started = make_orch()
        _remote(monkeypatch, o, None)
        assert c.post("/trigger", json={}, headers=_bearer(PTOKEN)).status_code == 200


class TestResetAuth:
    def _stuck(self, o):
        o._running = True
        o._last_heartbeat = time.time() - 30
        o._progress.update({"running": True, "phase": "dns"})

    def test_reset_without_header_is_401_and_unblocks_nothing(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, None)
        self._stuck(o)
        r = c.post("/trigger/reset")
        assert r.status_code == 401
        assert o._running is True
        assert o._progress["phase"] == "dns" and o._progress["running"] is True

    def test_reset_wrong_token_is_401(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, None)
        self._stuck(o)
        assert c.post("/trigger/reset", headers=_bearer("wrong")).status_code == 401
        assert o._running is True

    def test_reset_viewer_is_403(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, VIEWER)
        self._stuck(o)
        assert c.post("/trigger/reset", headers=_bearer(SESSION)).status_code == 403
        assert o._running is True

    def test_reset_service_identity_rejected(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, SERVICE)
        self._stuck(o)
        assert c.post("/trigger/reset", headers=_bearer(SESSION)).status_code in (401, 403)
        assert o._running is True

    def test_reset_empty_pipeline_token_authenticates_nobody(self, make_orch, monkeypatch):
        o, c, _ = make_orch("")
        _remote(monkeypatch, o, None)
        self._stuck(o)
        assert c.post("/trigger/reset", headers={"Authorization": "Bearer "}).status_code == 401
        assert o._running is True

    def test_reset_with_pipeline_token_unblocks(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, None)
        self._stuck(o)
        r = c.post("/trigger/reset", headers=_bearer(PTOKEN))
        assert r.status_code == 200 and r.json()["was_running"] is True
        assert o._running is False

    def test_reset_with_analyst_session_unblocks(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, ANALYST)
        self._stuck(o)
        assert c.post("/trigger/reset", headers=_bearer(SESSION)).status_code == 200
        assert o._running is False


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self.ok = status < 400
        self._body = body if body is not None else {}

    def json(self):
        return self._body


def _spy_session(monkeypatch, o, rep_status=200):
    calls = []

    def get(url, **kw):
        calls.append((url, dict(kw.get("headers") or {})))
        if "/reputation" in url:
            return _Resp(rep_status, {"risk_score": 0} if rep_status == 200 else {})
        return _Resp(200, {})
    monkeypatch.setattr(o, "_session", SimpleNamespace(get=get))
    return calls


def _gather(o):
    return o._gather_intelligence("acme-typo.example",
                                  o.TriggerRequest(include_whois=True, include_reputation=True))


def _has_auth(headers):
    return any(k.lower() == "authorization" for k in headers)


class TestReputationCallCarriesPipelineToken:
    def test_token_sent_to_reputation_only(self, make_orch, monkeypatch):
        o, _, _ = make_orch()
        calls = _spy_session(monkeypatch, o)
        _gather(o)
        rep = [h for u, h in calls if "/reputation" in u]
        other = [(u, h) for u, h in calls if "/reputation" not in u]
        assert len(rep) == 1
        assert rep[0].get("Authorization") == f"Bearer {PTOKEN}"
        assert len(other) >= 4  # dns, cert, http, whois
        for u, h in other:
            assert not _has_auth(h), f"Authorization inviato a {u}"
            assert PTOKEN not in " ".join(map(str, h.values()))

    @pytest.mark.parametrize("configured", [None, ""])
    def test_no_header_when_token_not_configured(self, make_orch, monkeypatch, configured):
        o, _, _ = make_orch(configured)
        calls = _spy_session(monkeypatch, o)
        _gather(o)
        assert any("/reputation" in u for u, _ in calls)
        assert not any(_has_auth(h) for _, h in calls)

    @pytest.mark.parametrize("status", [401, 403])
    def test_reputation_auth_refusal_leaves_distinguishable_log_and_failed_module(
            self, make_orch, monkeypatch, caplog, status):
        o, _, _ = make_orch()
        _spy_session(monkeypatch, o, rep_status=status)
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            intel = _gather(o)
        assert intel["reputation"] is None
        assert o._module_failed(intel["reputation"]) is True
        msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        # distinguibile dal generico "HTTP 4xx": nomina l'autenticazione / il PIPELINE_TOKEN
        assert any("reputation" in m.lower() and str(status) in m
                   and ("PIPELINE_TOKEN" in m or "auth" in m.lower()) for m in msgs), msgs


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
# Giro 2 (verifier INSUFFICIENTE, security-reviewer APPROVATO CON RILIEVI)
# Nomi assunti: `services.orchestrator.AUTH_REMOTE_MAX_CONCURRENT` (env omonima, default 4).
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
import http.client
import json as _json
import threading

import uvicorn


def _wait_for(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


class _LiveServer:
    """uvicorn vero in un thread, porta effimera: la concorrenza del pool di thread di anyio esiste solo qui."""

    def __init__(self, app):
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        assert _wait_for(lambda: self.server.started, 10), "uvicorn non e' partito"
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(10)

    def request(self, method, path, headers=None, body=None, timeout=10):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            hdrs = dict(headers or {})
            data = None
            if body is not None:
                data = _json.dumps(body)
                hdrs["Content-Type"] = "application/json"
            t0 = time.monotonic()
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            resp.read()
            return resp.status, dict(resp.getheaders()), time.monotonic() - t0
        finally:
            conn.close()


class TestRemoteAuthConcurrencyH1:
    LIMIT = 2
    EXTRA = 6

    def test_remote_verifications_are_bounded_and_do_not_starve_other_requests(self, monkeypatch, make_orch):
        monkeypatch.setenv("AUTH_REMOTE_MAX_CONCURRENT", str(self.LIMIT))
        o, _, started = make_orch()
        release = threading.Event()
        lock = threading.Lock()
        state = {"inflight": 0, "peak": 0, "calls": 0}

        def blocking_verify(token, url=None, *a, **kw):
            with lock:
                state["inflight"] += 1
                state["calls"] += 1
                state["peak"] = max(state["peak"], state["inflight"])
            try:
                release.wait(15)
                return None
            finally:
                with lock:
                    state["inflight"] -= 1
        monkeypatch.setattr(o, "verify_token_remote", blocking_verify, raising=False)
        import shared.auth
        monkeypatch.setattr(shared.auth, "verify_token_remote", blocking_verify)

        total = self.LIMIT + self.EXTRA
        results = []

        def junk():
            try:
                results.append(srv.request("POST", "/trigger", headers=_bearer("junk"), body={}, timeout=20))
            except Exception as e:  # il test riportera' il guasto
                results.append(("err", repr(e), 0))

        with _LiveServer(o.app) as srv:
            threads = [threading.Thread(target=junk, daemon=True) for _ in range(total)]
            try:
                for t in threads:
                    t.start()
                _wait_for(lambda: state["calls"] >= self.LIMIT, 3)
                time.sleep(0.6)  # le richieste in eccesso, se non rifiutate, entrerebbero in verify adesso

                # (1) al piu' LIMIT verifiche remote in volo
                assert state["peak"] <= self.LIMIT, f"{state['peak']} verifiche remote in volo, limite {self.LIMIT}"
                # (2) le richieste in eccesso: 503 con Retry-After, subito, senza chiamare verify
                excess = [r for r in results if r[0] == 503]
                assert len(excess) == self.EXTRA, f"503 ricevuti: {len(excess)}; risultati: {results}"
                assert all(r[2] < 1.0 for r in excess)
                assert all(any(k.lower() == "retry-after" for k in r[1]) for r in excess)
                assert state["calls"] == self.LIMIT

                # (3) con le verifiche bloccate: PIPELINE_TOKEN valido e /health rispondono subito
                status, _, dt = srv.request("POST", "/trigger", headers=_bearer(PTOKEN), body={}, timeout=5)
                assert status == 200 and dt < 1.0, (status, dt)
                status, _, dt = srv.request("GET", "/health", timeout=5)
                assert status == 200 and dt < 1.0, (status, dt)
            finally:
                release.set()
                for t in threads:
                    t.join(10)
        # sbloccate, le due verifiche entrate rispondono 401 (verify -> None)
        assert sorted(r[0] for r in results if r[0] != 503) == [401] * self.LIMIT


class TestPipelineTokenWhitespaceM1:
    @pytest.mark.parametrize("header", ["Bearer    ", "Bearer   x", "Bearer"])
    def test_whitespace_only_token_authenticates_nobody_on_trigger(self, make_orch, monkeypatch, header):
        o, c, started = make_orch("   ")
        _remote(monkeypatch, o, None)
        assert c.post("/trigger", json={}, headers={"Authorization": header}).status_code == 401
        assert c.post("/trigger/reset", headers={"Authorization": header}).status_code == 401
        assert started == []

    def test_outer_whitespace_in_env_is_ignored(self, make_orch, monkeypatch):
        o, c, started = make_orch(" " + PTOKEN + " ")
        _remote(monkeypatch, o, None)
        assert c.post("/trigger", json={}, headers=_bearer(PTOKEN)).status_code == 200
        assert len(started) == 1

    def test_outer_whitespace_in_env_is_ignored_for_the_header_sent_to_reputation(self, make_orch, monkeypatch):
        o, _, _ = make_orch(" " + PTOKEN + " ")
        calls = _spy_session(monkeypatch, o)
        _gather(o)
        rep = [h for u, h in calls if "/reputation" in u]
        assert rep[0].get("Authorization") == f"Bearer {PTOKEN}"

    def test_whitespace_only_token_sends_no_header_to_reputation(self, make_orch, monkeypatch):
        o, _, _ = make_orch("   ")
        calls = _spy_session(monkeypatch, o)
        _gather(o)
        assert not any(_has_auth(h) for _, h in calls)


class TestStartupWarningsM2:
    def _warnings(self, caplog):
        return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]

    def test_empty_token_warns_even_with_case_manager_url_set(self, make_orch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            make_orch("")   # _load imposta CASE_MANAGER_URL
        assert any("PIPELINE_TOKEN" in m and "/trigger" in m for m in self._warnings(caplog)), self._warnings(caplog)

    def test_missing_token_warns(self, make_orch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            make_orch(None)
        assert any("PIPELINE_TOKEN" in m and "/trigger" in m for m in self._warnings(caplog)), self._warnings(caplog)

    def test_short_token_warns_about_length(self, make_orch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            make_orch("short-test-token")
        assert any("PIPELINE_TOKEN" in m and ("32" in m or "lungh" in m.lower() or "length" in m.lower())
                   for m in self._warnings(caplog)), self._warnings(caplog)

    def test_long_enough_token_does_not_warn(self, make_orch, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            make_orch("t" * 40)
        assert not any("PIPELINE_TOKEN" in m for m in self._warnings(caplog))


class TestMalformedAuthMeL1:
    """La risposta di /auth/me (o l'eccezione di verify_token_remote) non e' fidata: rifiuto, mai 200 ne' 500."""

    def _post(self, make_orch, monkeypatch, user, path="/trigger"):
        o, c, started = make_orch()
        _remote(monkeypatch, o, user)
        r = c.post(path, json={}, headers=_bearer(SESSION)) if path == "/trigger" \
            else c.post(path, headers=_bearer(SESSION))
        return r, o, started

    @pytest.mark.parametrize("user", [["manage_cases"], "manage_cases", 42, True], ids=["list", "str", "int", "bool"])
    def test_non_dict_response_is_401(self, make_orch, monkeypatch, user):
        r, o, started = self._post(make_orch, monkeypatch, user)
        assert r.status_code == 401
        assert started == []

    @pytest.mark.parametrize("perms", ["manage_cases", {"manage_cases": 1}, None, 7, "view,manage_cases"],
                             ids=["str", "dict", "none", "int", "csv"])
    def test_non_list_permissions_never_pass(self, make_orch, monkeypatch, perms):
        user = {"id": 2, "username": "analyst-test", "role": "analyst", "permissions": perms}
        r, o, started = self._post(make_orch, monkeypatch, user)
        assert r.status_code in (401, 403), r.status_code
        assert started == []

    @pytest.mark.parametrize("role", ["MISSING", None, 5, ["service"], ""], ids=["missing", "none", "int", "list", "empty"])
    def test_missing_or_non_string_role_is_rejected(self, make_orch, monkeypatch, role):
        user = {"id": 2, "username": "x", "permissions": ["manage_cases", "view"]}
        if role != "MISSING":
            user["role"] = role
        r, o, started = self._post(make_orch, monkeypatch, user)
        assert r.status_code in (401, 403), r.status_code
        assert started == []

    @pytest.mark.parametrize("role", ["Service", "SERVICE"])
    def test_service_role_in_any_spelling_is_rejected(self, make_orch, monkeypatch, role):
        user = dict(SERVICE, role=role)
        r, o, started = self._post(make_orch, monkeypatch, user)
        assert r.status_code in (401, 403)
        assert started == []

    @pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyError("x"), ValueError("v")], ids=["runtime", "key", "value"])
    def test_exception_from_remote_verification_is_401_not_500(self, make_orch, monkeypatch, exc):
        o, c, started = make_orch()

        def boom(*a, **kw):
            raise exc
        monkeypatch.setattr(o, "verify_token_remote", boom, raising=False)
        import shared.auth
        monkeypatch.setattr(shared.auth, "verify_token_remote", boom)
        c2 = TestClient(o.app, raise_server_exceptions=False)
        for path in ("/trigger", "/trigger/reset"):
            r = c2.post(path, json={}, headers=_bearer(SESSION))
            assert r.status_code == 401, (path, r.status_code)
        assert started == []

    def test_malformed_reset_does_not_unblock(self, make_orch, monkeypatch):
        o, c, _ = make_orch()
        _remote(monkeypatch, o, {"role": "analyst", "permissions": "manage_cases"})
        o._running = True
        o._last_heartbeat = time.time() - 30
        assert c.post("/trigger/reset", headers=_bearer(SESSION)).status_code in (401, 403)
        assert o._running is True


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
# Giro 3: il posto del tetto non si libera con la cancellazione dell'await; service con spazi; log del 503.
# Nomi assunti: `services.orchestrator._auth_remote_slots` (semaforo: `acquire(blocking=False)` dice se c'e' posto),
# `_require_pipeline_auth(authorization)` chiamabile come coroutine, `AUTH_REMOTE_MAX_CONCURRENT`.
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
import asyncio


class TestSlotHeldWhileVerifyThreadRuns:
    def test_cancelling_the_await_does_not_free_the_slot_until_the_thread_ends(self, monkeypatch, make_orch):
        monkeypatch.setenv("AUTH_REMOTE_MAX_CONCURRENT", "1")
        o, _, _ = make_orch()
        release = threading.Event()
        entered = threading.Event()
        finished = threading.Event()

        def blocking_verify(token, url=None, *a, **kw):
            entered.set()
            try:
                release.wait(15)
                return None
            finally:
                finished.set()
        monkeypatch.setattr(o, "verify_token_remote", blocking_verify, raising=False)

        def slot_is_free():
            if o._auth_remote_slots.acquire(blocking=False):
                o._auth_remote_slots.release()
                return True
            return False

        async def scenario():
            task = asyncio.ensure_future(o._require_pipeline_auth("Bearer junk"))
            for _ in range(300):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set(), "la verifica remota non e' partita"
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            return slot_is_free()

        try:
            free_while_thread_runs = asyncio.run(scenario())
            assert free_while_thread_runs is False, \
                "il posto e' tornato libero mentre il thread di verify_token_remote e' ancora in corso"
            assert not finished.is_set()
        finally:
            release.set()
        assert finished.wait(5)
        assert _wait_for(slot_is_free, 3), "il posto non e' tornato libero a thread finito"

    def test_second_verification_during_orphaned_thread_gets_503(self, monkeypatch, make_orch):
        monkeypatch.setenv("AUTH_REMOTE_MAX_CONCURRENT", "1")
        o, _, _ = make_orch()
        from fastapi import HTTPException
        release = threading.Event()
        entered = threading.Event()
        calls = []

        def blocking_verify(token, url=None, *a, **kw):
            calls.append(token)
            entered.set()
            release.wait(15)
            return None
        monkeypatch.setattr(o, "verify_token_remote", blocking_verify, raising=False)

        async def scenario():
            task = asyncio.ensure_future(o._require_pipeline_auth("Bearer junk"))
            for _ in range(300):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            try:
                await asyncio.wait_for(o._require_pipeline_auth("Bearer junk2"), 1.0)
            except HTTPException as e:
                return e.status_code
            except asyncio.TimeoutError:
                return "timeout"
            return "ok"

        try:
            assert asyncio.run(scenario()) == 503
            assert calls == ["junk"]
        finally:
            release.set()


class TestServiceRoleWithSurroundingSpaces:
    @pytest.mark.parametrize("role", ["service ", " Service", " service ", "\tservice"])
    def test_service_identity_with_spaces_is_403(self, make_orch, monkeypatch, role):
        o, c, started = make_orch()
        _remote(monkeypatch, o, dict(SERVICE, role=role))
        assert c.post("/trigger", json={}, headers=_bearer(SESSION)).status_code == 403
        assert started == []


class TestBusyWarningIsRateLimited:
    def test_503_leaves_one_warning_per_window(self, monkeypatch, make_orch, caplog):
        monkeypatch.setenv("AUTH_REMOTE_MAX_CONCURRENT", "1")
        o, c, _ = make_orch()
        calls = _remote(monkeypatch, o, None)
        assert o._auth_remote_slots.acquire(blocking=False)   # il tetto e' raggiunto
        try:
            with caplog.at_level(logging.WARNING, logger="orchestrator"):
                t0 = time.monotonic()
                codes = [c.post("/trigger", json={}, headers=_bearer("junk")).status_code for _ in range(10)]
                assert time.monotonic() - t0 < 1.0, "il test presume 10 rifiuti in meno di una finestra"
        finally:
            o._auth_remote_slots.release()
        assert codes == [503] * 10 and calls == []
        busy = [r for r in caplog.records if r.name == "orchestrator" and r.levelno >= logging.WARNING
                and ("AUTH_REMOTE_MAX_CONCURRENT" in r.getMessage() or "tetto" in r.getMessage().lower()
                     or "concurr" in r.getMessage().lower())]
        assert len(busy) == 1, [r.getMessage() for r in caplog.records]


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
# Giro 4: un await annullato mentre il lavoro e' ancora IN CODA non deve far perdere il posto; niente doppio rilascio.
# Nomi assunti: `services.orchestrator._auth_remote_pool` (executor dedicato, `submit`), `_auth_remote_slots`
# (sostituibile con un BoundedSemaphore: la dipendenza lo legge come globale del modulo a ogni richiesta).
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
class _SpySlots(threading.BoundedSemaphore):
    """BoundedSemaphore che registra i rilasci di troppo (ValueError), anche se il chiamante li inghiotte."""

    def __init__(self, n):
        super().__init__(n)
        self.over_releases = 0

    def release(self, *a, **kw):
        try:
            return super().release(*a, **kw)
        except ValueError:
            self.over_releases += 1
            raise


def _free_slots(sem, n):
    """Quanti posti si riescono a prendere ora (poi li restituisce): vale n se sono tutti liberi."""
    got = 0
    while got < n + 1 and sem.acquire(blocking=False):
        got += 1
    for _ in range(got):
        sem.release()
    return got


class TestSlotNotLeakedWhenCancelledInQueue:
    N = 2

    def _setup(self, monkeypatch, make_orch):
        monkeypatch.setenv("AUTH_REMOTE_MAX_CONCURRENT", str(self.N))
        o, _, _ = make_orch()
        spy = _SpySlots(self.N)
        monkeypatch.setattr(o, "_auth_remote_slots", spy)
        return o, spy

    def test_cancel_while_queued_in_the_dedicated_pool_frees_the_slot(self, monkeypatch, make_orch):
        o, spy = self._setup(monkeypatch, make_orch)
        gate = threading.Event()
        busy = [threading.Event() for _ in range(self.N)]
        verify_calls = []
        monkeypatch.setattr(o, "verify_token_remote", lambda *a, **kw: verify_calls.append(a) or None, raising=False)

        def foreign(started):
            started.set()
            gate.wait(15)

        async def scenario():
            # tutti i worker del pool dedicato sono occupati da lavoro estraneo: il lavoro della dipendenza resta in coda
            futures = [o._auth_remote_pool.submit(foreign, e) for e in busy]
            for e in busy:
                assert await asyncio.get_running_loop().run_in_executor(None, e.wait, 5), "worker non occupato"
            task = asyncio.ensure_future(o._require_pipeline_auth("Bearer junk"))
            await asyncio.sleep(0.1)          # la dipendenza ha preso il posto e accodato il lavoro
            assert not task.done()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            return futures

        futures = []
        try:
            futures = asyncio.run(scenario())
        finally:
            gate.set()
        for f in futures:
            f.result(5)
        # il lavoro cancellato in coda non e' mai partito: nessuna chiamata a verify, e il posto deve essere tornato
        assert _wait_for(lambda: _free_slots(spy, self.N) == self.N, 3), \
            f"posti acquisibili: {_free_slots(spy, self.N)} su {self.N}: il posto del lavoro annullato in coda e' perso"
        assert verify_calls == []
        assert spy.over_releases == 0

    def test_no_double_release_after_a_normal_cycle_and_a_cancelled_in_flight_one(self, monkeypatch, make_orch):
        o, spy = self._setup(monkeypatch, make_orch)
        from fastapi import HTTPException
        release = threading.Event()
        entered = threading.Event()
        mode = {"slow": False}

        def verify(token, url=None, *a, **kw):
            if mode["slow"]:
                entered.set()
                release.wait(15)
            return None
        monkeypatch.setattr(o, "verify_token_remote", verify, raising=False)

        async def scenario():
            with pytest.raises(HTTPException) as exc:        # ciclo normale: verifica completata (token non valido)
                await o._require_pipeline_auth("Bearer junk")
            assert exc.value.status_code == 401
            mode["slow"] = True
            task = asyncio.ensure_future(o._require_pipeline_auth("Bearer junk"))
            for _ in range(300):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        try:
            asyncio.run(scenario())
        finally:
            release.set()
        assert _wait_for(lambda: _free_slots(spy, self.N) == self.N, 3)
        assert _free_slots(spy, self.N + 2) == self.N, "i posti non possono superare il massimo"
        assert spy.over_releases == 0, "BoundedSemaphore ha segnalato un rilascio di troppo"
