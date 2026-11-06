"""Tests for shared/auth.py and services/case_manager.py"""

import os
import tempfile

# Use a temp DB before importing the service
_tmpdir = tempfile.mkdtemp()
os.environ["CASES_DB"] = os.path.join(_tmpdir, "test_cases.db")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "admin_password_123"

from shared.auth import (hash_password, verify_password, generate_token,
                         hash_token, permissions_for_role)
from fastapi.testclient import TestClient
from services.case_manager import app

client = TestClient(app)


# ═══════════════════════════════════════════
# AUTH PRIMITIVES
# ═══════════════════════════════════════════

class TestAuthPrimitives:
    def test_password_roundtrip(self):
        h, salt = hash_password("secret123")
        assert verify_password("secret123", h, salt) is True

    def test_password_wrong(self):
        h, salt = hash_password("secret123")
        assert verify_password("wrong", h, salt) is False

    def test_password_unique_salts(self):
        h1, s1 = hash_password("same")
        h2, s2 = hash_password("same")
        assert s1 != s2
        assert h1 != h2  # different salt → different hash

    def test_token_unique(self):
        assert generate_token() != generate_token()

    def test_token_hash_deterministic(self):
        t = generate_token()
        assert hash_token(t) == hash_token(t)

    def test_token_hash_hides_token(self):
        t = generate_token()
        assert hash_token(t) != t

    def test_role_presets(self):
        assert "manage_users" in permissions_for_role("admin")
        assert "manage_users" not in permissions_for_role("analyst")
        assert permissions_for_role("viewer") == ["view"]

    def test_unknown_role_defaults_viewer(self):
        assert permissions_for_role("nonexistent") == ["view"]

    def test_served_pbkdf2_cost_is_not_lowered(self, tmp_path):
        """BUILD-06 — il costo PBKDF2 che il codice servito usa non scende sotto
        le 600.000 iterazioni che `shared/auth.py` dichiara (raccomandazione
        OWASP per PBKDF2-HMAC-SHA256), qualunque cosa faccia la suite.

        `tests/conftest.py` abbassa `shared.auth.PBKDF2_ITERATIONS` nel solo
        processo di test per tenere breve la suite. Da dentro quel processo il
        valore servito non si vede più: qui lo si legge in un interprete NUOVO,
        che non ha mai caricato l'override, con l'ambiente del processo di test
        e `PYTHONPATH` sul repo. Si prova su due piani: la costante, e l'EFFETTO,
        cioè le iterazioni che `hash_password` e `verify_password` passano
        davvero a `hashlib.pbkdf2_hmac` (sostituito, prima dell'import, da una
        spia che registra e non calcola nulla). Il secondo piano prende un
        letterale messo al posto della costante in una delle due funzioni. Il
        figlio deve inoltre aver importato lo stesso `shared/auth.py` del
        processo padre: altrimenti il valore letto sarebbe quello di un'altra
        copia del codice.

        Cosa NON prova: una lettura del costo da `environ` la vede solo se la
        variabile è già nell'ambiente del processo di test. La protezione contro
        quella lettura sta nel fatto che `shared/auth.py` non legge l'ambiente
        per questo valore; il test non la sostituisce. Non copre i punti di
        chiamata nei servizi, né un calcolo che aggiri `hashlib.pbkdf2_hmac`, né
        l'algoritmo o la lunghezza della chiave passati a PBKDF2: guarda solo le
        iterazioni. Se `shared/auth.py` cambiasse algoritmo la spia non vedrebbe
        chiamate e il test fallirebbe: va riscritto per il nuovo algoritmo, non
        allentato."""
        import json
        import subprocess
        import sys
        import textwrap
        from pathlib import Path

        import shared.auth as parent_auth

        probe = textwrap.dedent("""\
            import hashlib, json
            seen = []
            def spy(*args, **kwargs):
                seen.append(kwargs["iterations"] if "iterations" in kwargs else args[3])
                return b"\\x00" * 32
            hashlib.pbkdf2_hmac = spy
            import shared.auth as a
            a.hash_password("x", "ab")
            n_hash = len(seen)
            a.verify_password("x", "0" * 64, "ab")
            print(json.dumps({"file": a.__file__, "constant": a.PBKDF2_ITERATIONS,
                              "hash": seen[:n_hash], "verify": seen[n_hash:]}))
        """)
        repo = Path(__file__).resolve().parent.parent
        env = dict(os.environ, PYTHONPATH=str(repo), PYTHONDONTWRITEBYTECODE="1")
        # cwd fuori dal repo: l'import deve riuscire per il PYTHONPATH, non perché
        # `-c` mette la directory corrente in testa a sys.path.
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=30, env=env, cwd=tmp_path)
        assert proc.returncode == 0, (
            f"l'interprete pulito non ha importato shared.auth: rc={proc.returncode}, "
            f"stderr={proc.stderr.strip()!r}")
        report = json.loads(proc.stdout.strip().splitlines()[-1])

        assert Path(report["file"]).resolve() == Path(parent_auth.__file__).resolve(), (
            f"l'interprete pulito ha importato {report['file']}, il processo di test "
            f"{parent_auth.__file__}: il valore letto non è quello del codice sotto "
            "test. Controllare PYTHONPATH e il percorso da cui parte pytest.")
        assert report["constant"] >= 600_000, (
            f"shared.auth.PBKDF2_ITERATIONS vale {report['constant']} in un interprete "
            "pulito: sotto le 600.000 iterazioni dichiarate in shared/auth.py. È il costo "
            "con cui il container salva e verifica le password, non quello ridotto "
            "che tests/conftest.py usa solo nel processo di test.")
        for fn in ("hash", "verify"):
            assert report[fn], (
                f"{fn}_password non ha chiamato hashlib.pbkdf2_hmac: la spia non vede il "
                "costo, quindi il test non prova nulla. Se l'algoritmo è cambiato, "
                "riscrivere la spia per il nuovo.")
            assert min(report[fn]) >= 600_000, (
                f"{fn}_password passa {min(report[fn])} iterazioni a PBKDF2 in un interprete "
                "pulito: sotto le 600.000 dichiarate in shared/auth.py, anche se la "
                f"costante vale {report['constant']}. Un letterale ha preso il posto della costante?")


# ═══════════════════════════════════════════
# AUTH FLOW
# ═══════════════════════════════════════════

def _login(username, password):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestAuthFlow:
    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_login_success(self):
        resp = _login("admin", "admin_password_123")
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_login_wrong_password(self):
        resp = _login("admin", "wrongpassword")
        assert resp.status_code == 401

    def test_login_nonexistent_user(self):
        resp = _login("ghost", "whatever123")
        assert resp.status_code == 401

    def test_me_requires_token(self):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_me_with_token(self):
        token = _login("admin", "admin_password_123").json()["token"]
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"
        assert resp.json()["role"] == "admin"

    def test_invalid_token_rejected(self):
        resp = client.get("/auth/me", headers=_auth_header("garbage-token"))
        assert resp.status_code == 401

    def test_logout_revokes_token(self):
        token = _login("admin", "admin_password_123").json()["token"]
        client.post("/auth/logout", headers=_auth_header(token))
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401


# ═══════════════════════════════════════════
# USER MANAGEMENT + RBAC
# ═══════════════════════════════════════════

class TestUserManagement:
    def _admin_token(self):
        return _login("admin", "admin_password_123").json()["token"]

    def test_create_user(self):
        token = self._admin_token()
        resp = client.post("/users", headers=_auth_header(token), json={
            "username": "analyst1", "password": "analyst_pw_123", "role": "analyst"
        })
        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"

    def test_viewer_cannot_create_users(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "viewer1", "password": "viewer_pw_123", "role": "viewer"
        })
        viewer_token = _login("viewer1", "viewer_pw_123").json()["token"]
        resp = client.post("/users", headers=_auth_header(viewer_token), json={
            "username": "hacker", "password": "hacker_pw_123", "role": "admin"
        })
        assert resp.status_code == 403

    def test_weak_password_rejected(self):
        token = self._admin_token()
        resp = client.post("/users", headers=_auth_header(token), json={
            "username": "weak", "password": "short", "role": "viewer"
        })
        assert resp.status_code == 422

    def test_user_changes_own_password_with_current(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "selfpw", "password": "old_password_1", "role": "viewer"
        })
        tok = _login("selfpw", "old_password_1").json()["token"]
        uid = client.get("/auth/me", headers=_auth_header(tok)).json()["id"]
        # correct current password → allowed
        r = client.post(f"/users/{uid}/password", headers=_auth_header(tok),
                        json={"current_password": "old_password_1", "password": "new_password_2"})
        assert r.status_code == 200
        # old password no longer works, new one does
        assert _login("selfpw", "old_password_1").status_code == 401
        assert _login("selfpw", "new_password_2").status_code == 200

    def test_self_password_change_requires_correct_current(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "selfpw2", "password": "orig_password_1", "role": "viewer"
        })
        tok = _login("selfpw2", "orig_password_1").json()["token"]
        uid = client.get("/auth/me", headers=_auth_header(tok)).json()["id"]
        # wrong current password → 403
        r = client.post(f"/users/{uid}/password", headers=_auth_header(tok),
                        json={"current_password": "WRONG", "password": "another_pw_9"})
        assert r.status_code == 403
        # missing current password → 400
        r2 = client.post(f"/users/{uid}/password", headers=_auth_header(tok),
                         json={"password": "another_pw_9"})
        assert r2.status_code == 400

    def test_admin_resets_other_without_current(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "resetme", "password": "initial_pw_1", "role": "analyst"
        })
        uid = None
        users = client.get("/users", headers=_auth_header(admin)).json()["users"]
        uid = next(u["id"] for u in users if u["username"] == "resetme")
        # admin reset needs no current_password
        r = client.post(f"/users/{uid}/password", headers=_auth_header(admin),
                        json={"password": "admin_set_pw_2"})
        assert r.status_code == 200
        assert _login("resetme", "admin_set_pw_2").status_code == 200

    def test_user_cannot_change_others_password(self):
        admin = self._admin_token()
        for n in ["viewerA", "viewerB"]:
            client.post("/users", headers=_auth_header(admin), json={
                "username": n, "password": f"{n}_password_1", "role": "viewer"
            })
        tokA = _login("viewerA", "viewerA_password_1").json()["token"]
        users = client.get("/users", headers=_auth_header(admin)).json()["users"]
        uidB = next(u["id"] for u in users if u["username"] == "viewerB")
        r = client.post(f"/users/{uidB}/password", headers=_auth_header(tokA),
                        json={"current_password": "x", "password": "hijack_pw_9"})
        assert r.status_code == 403

    def test_duplicate_username_rejected(self):
        token = self._admin_token()
        client.post("/users", headers=_auth_header(token), json={
            "username": "dup", "password": "dup_password_1", "role": "viewer"
        })
        resp = client.post("/users", headers=_auth_header(token), json={
            "username": "dup", "password": "dup_password_2", "role": "viewer"
        })
        assert resp.status_code == 409

    def test_custom_permissions(self):
        token = self._admin_token()
        resp = client.post("/users", headers=_auth_header(token), json={
            "username": "custom1", "password": "custom_pw_123", "role": "viewer",
            "permissions": ["view", "add_notes"]
        })
        assert resp.status_code == 200
        assert set(resp.json()["permissions"]) == {"view", "add_notes"}

    def test_invalid_permission_rejected(self):
        token = self._admin_token()
        resp = client.post("/users", headers=_auth_header(token), json={
            "username": "bad", "password": "bad_password_1", "role": "viewer",
            "permissions": ["view", "delete_everything"]
        })
        assert resp.status_code == 400

    def test_cannot_disable_last_admin(self):
        token = self._admin_token()
        # admin is user id 1
        resp = client.patch("/users/1", headers=_auth_header(token), json={"active": False})
        assert resp.status_code == 400


# ═══════════════════════════════════════════
# CASE LIFECYCLE
# ═══════════════════════════════════════════

class TestCaseLifecycle:
    def _admin_token(self):
        return _login("admin", "admin_password_123").json()["token"]

    def test_ingest_creates_case(self):
        token = self._admin_token()
        resp = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil1.com", "client": "acme", "classification": "suspicious",
            "severity": "HIGH", "rationale": "MX without A record"
        })
        assert resp.status_code == 200
        assert resp.json()["created"] is True

    def test_ingest_idempotent_update(self):
        token = self._admin_token()
        client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil2.com", "client": "acme", "classification": "parking"
        })
        resp = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil2.com", "client": "acme", "classification": "suspicious"
        })
        assert resp.json().get("updated") is True

    def test_list_cases(self):
        token = self._admin_token()
        client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil3.com", "client": "acme"
        })
        resp = client.get("/cases", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_status_change_audited(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil4.com", "client": "acme"
        }).json()["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                     json={"status": "in_progress"})
        detail = client.get(f"/cases/{cid}", headers=_auth_header(token)).json()
        assert detail["case"]["status"] == "in_progress"
        actions = [h["action"] for h in detail["history"]]
        assert "status_changed" in actions

    def test_invalid_status_rejected(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil5.com", "client": "acme"
        }).json()["id"]
        resp = client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                            json={"status": "magic"})
        assert resp.status_code == 422

    def test_closed_case_can_be_reopened(self):
        # A closed case must not be a dead end: closing then reopening must work
        # (e.g. an FP later found to be a real threat, or a mistaken close).
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "reopen-me.com", "client": "acme"
        }).json()["id"]
        # close as FP
        client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                     json={"status": "closed_fp"})
        d1 = client.get(f"/cases/{cid}", headers=_auth_header(token)).json()
        assert d1["case"]["status"] == "closed_fp"
        # reopen → in_progress
        resp = client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                            json={"status": "in_progress"})
        assert resp.status_code == 200
        d2 = client.get(f"/cases/{cid}", headers=_auth_header(token)).json()
        assert d2["case"]["status"] == "in_progress"

    def test_assign_case(self):
        token = self._admin_token()
        client.post("/users", headers=_auth_header(token), json={
            "username": "assignee1", "password": "assignee_pw_1", "role": "analyst"
        })
        users = client.get("/users", headers=_auth_header(token)).json()["users"]
        aid = next(u["id"] for u in users if u["username"] == "assignee1")
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil6.com", "client": "acme"
        }).json()["id"]
        resp = client.post(f"/cases/{cid}/assign", headers=_auth_header(token),
                          json={"assignee_id": aid})
        assert resp.status_code == 200
        assert resp.json()["assignee_name"] == "assignee1"

    def test_add_note(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil7.com", "client": "acme"
        }).json()["id"]
        resp = client.post(f"/cases/{cid}/notes", headers=_auth_header(token),
                          json={"note": "Verified via OSINT, legitimate Spanish company"})
        assert resp.status_code == 200
        detail = client.get(f"/cases/{cid}", headers=_auth_header(token)).json()
        assert len(detail["notes"]) == 1

    def test_empty_note_rejected(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil8.com", "client": "acme"
        }).json()["id"]
        resp = client.post(f"/cases/{cid}/notes", headers=_auth_header(token),
                          json={"note": "   "})
        assert resp.status_code == 422

    def test_closed_case_no_reopen_on_low(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil9.com", "client": "acme"
        }).json()["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                     json={"status": "closed_fp"})
        resp = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil9.com", "client": "acme", "severity": "LOW"
        })
        assert resp.json()["status"] == "closed_fp"

    def test_closed_case_reopens_on_critical(self):
        token = self._admin_token()
        cid = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil10.com", "client": "acme"
        }).json()["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                     json={"status": "closed_fp"})
        resp = client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": "evil10.com", "client": "acme", "severity": "CRITICAL"
        })
        assert resp.json().get("reopened") is True

    def test_summary(self):
        token = self._admin_token()
        resp = client.get("/summary", headers=_auth_header(token))
        assert resp.status_code == 200
        assert "by_status" in resp.json()


# ═══════════════════════════════════════════
# PERMISSION ENFORCEMENT ON CASES
# ═══════════════════════════════════════════

class TestCasePermissions:
    def _admin_token(self):
        return _login("admin", "admin_password_123").json()["token"]

    def test_viewer_cannot_change_status(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "viewer2", "password": "viewer_pw_123", "role": "viewer"
        })
        cid = client.post("/cases/ingest", headers=_auth_header(admin), json={
            "domain": "perm1.com", "client": "acme"
        }).json()["id"]
        vtoken = _login("viewer2", "viewer_pw_123").json()["token"]
        resp = client.patch(f"/cases/{cid}/status", headers=_auth_header(vtoken),
                            json={"status": "closed_fp"})
        assert resp.status_code == 403

    def test_viewer_can_view(self):
        admin = self._admin_token()
        client.post("/users", headers=_auth_header(admin), json={
            "username": "viewer3", "password": "viewer_pw_123", "role": "viewer"
        })
        vtoken = _login("viewer3", "viewer_pw_123").json()["token"]
        resp = client.get("/cases", headers=_auth_header(vtoken))
        assert resp.status_code == 200


# ═══════════════════════════════════════════
# SERVICE TOKEN (service-to-service ingest)
# ═══════════════════════════════════════════

class TestServiceToken:
    """The orchestrator authenticates to /cases/ingest with a static service token."""

    def _reload_with_service_token(self, monkeypatch, token):
        import importlib
        monkeypatch.setenv("SERVICE_TOKEN", token)
        monkeypatch.setenv("CASES_DB", "/tmp/cm_svc.db")
        monkeypatch.setenv("ADMIN_PASSWORD", "admin_password_123")
        import services.case_manager as cm
        importlib.reload(cm)
        return cm

    def test_service_token_can_ingest(self, monkeypatch):
        cm = self._reload_with_service_token(monkeypatch, "super-secret-service-token-xyz")
        c = TestClient(cm.app)
        r = c.post("/cases/ingest",
                   headers={"Authorization": "Bearer super-secret-service-token-xyz"},
                   json={"domain": "svc-ingested.com", "client": "acme",
                         "classification": "suspicious", "severity": "HIGH"})
        assert r.status_code == 200
        assert r.json().get("created") is True

    def test_service_token_limited_permissions(self, monkeypatch):
        """Service token has manage_cases + view, but NOT manage_users."""
        cm = self._reload_with_service_token(monkeypatch, "super-secret-service-token-xyz")
        c = TestClient(cm.app)
        # Should be rejected from a manage_users-only endpoint
        r = c.get("/users", headers={"Authorization": "Bearer super-secret-service-token-xyz"})
        assert r.status_code == 403

    def test_wrong_service_token_rejected(self, monkeypatch):
        cm = self._reload_with_service_token(monkeypatch, "super-secret-service-token-xyz")
        c = TestClient(cm.app)
        r = c.post("/cases/ingest",
                   headers={"Authorization": "Bearer wrong-token"},
                   json={"domain": "x.com", "client": "acme"})
        assert r.status_code == 401

    def test_service_token_disabled_when_empty(self, monkeypatch):
        """When SERVICE_TOKEN is empty, no token should grant service access."""
        cm = self._reload_with_service_token(monkeypatch, "")
        c = TestClient(cm.app)
        r = c.post("/cases/ingest",
                   headers={"Authorization": "Bearer "},
                   json={"domain": "x.com", "client": "acme"})
        assert r.status_code in (401, 403)


def teardown_module(module):
    import importlib, os
    os.environ.pop("SERVICE_TOKEN", None)
    os.environ["CASES_DB"] = os.path.join(_tmpdir, "test_cases.db")
    import services.case_manager as cm
    importlib.reload(cm)


class TestLoginRateLimit:
    """Failed logins from one IP must be throttled to blunt brute-force."""
    def test_repeated_failures_get_429(self):
        import services.case_manager as cm
        cm._login_failures.clear()          # isolate from other tests
        orig = cm.LOGIN_MAX_FAILURES
        cm.LOGIN_MAX_FAILURES = 3
        try:
            codes = [client.post("/auth/login",
                                 json={"username": "admin", "password": "nope"}).status_code
                     for _ in range(5)]
            assert 429 in codes
            assert codes[:3] == [401, 401, 401]
            assert codes[3] == 429
        finally:
            cm.LOGIN_MAX_FAILURES = orig
            cm._login_failures.clear()


class TestClosedCaseEscalation:
    """A closed case must come back into the queue only when a re-scan reports a
    HIGHER severity than the one recorded. Routine re-scans at equal or lower
    severity must not undo the analyst's triage."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": "EscTest", "classification": "needs_review",
            "confidence": "low", "severity": severity, "rationale": "test",
        }).json()

    def _close(self, cid, token):
        return client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                            json={"status": "closed_fp"}).status_code

    def test_higher_severity_reopens(self):
        t = self._tok()
        cid = self._ingest("esc-up.com", "LOW", t)["id"]
        assert self._close(cid, t) == 200
        out = self._ingest("esc-up.com", "HIGH", t)
        assert out.get("reopened") is True
        assert out["status"] == "new"
        assert out["escalated_from"] == "LOW"
        assert out["escalated_to"] == "HIGH"

    def test_equal_severity_stays_closed(self):
        t = self._tok()
        cid = self._ingest("esc-eq.com", "MEDIUM", t)["id"]
        self._close(cid, t)
        out = self._ingest("esc-eq.com", "MEDIUM", t)
        assert out.get("reopened") is not True
        assert out["status"] == "closed_fp"

    def test_lower_severity_stays_closed(self):
        t = self._tok()
        cid = self._ingest("esc-down.com", "HIGH", t)["id"]
        self._close(cid, t)
        out = self._ingest("esc-down.com", "LOW", t)
        assert out.get("reopened") is not True
        assert out["status"] == "closed_fp"

    def test_open_case_never_reverts_to_new(self):
        # an in-progress case keeps its status when re-ingested
        t = self._tok()
        cid = self._ingest("esc-open.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t),
                     json={"status": "in_progress"})
        out = self._ingest("esc-open.com", "HIGH", t)
        assert out["status"] == "in_progress"
        assert out.get("updated") is True


# ═══════════════════════════════════════════
# CODE-26 — insufficient_data must not reopen a closed case
# ═══════════════════════════════════════════

class TestClosedCaseInsufficientDataNoReopen:
    """A collection failure (crt.sh unreachable, VT quota exhausted → classification
    `insufficient_data`) is not new evidence about the domain: it must not reopen a
    case an analyst already closed. `insufficient_data` currently carries severity
    MEDIUM (rank 2), which beats any case closed at severity_at_detection=LOW
    (rank 1) under the plain rank comparison in ingest_case, auto-reopening it
    (BUG-REGISTER CODE-26).

    The discriminant must be the classification, not the severity: a real
    re-classification (`needs_review`/MEDIUM, `phishing`/CRITICAL, ...) on a
    closed LOW case must still reopen it exactly as it does today."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token, classification="parking", client_name="C26Test"):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": client_name, "classification": classification,
            "confidence": "low", "severity": severity, "rationale": "test",
        }).json()

    def _get(self, cid, token):
        return client.get(f"/cases/{cid}", headers=_auth_header(token)).json()["case"]

    def _close(self, cid, token, status="closed_fp"):
        return client.patch(f"/cases/{cid}/status", headers=_auth_header(token),
                            json={"status": status}).status_code

    def test_insufficient_data_does_not_reopen_closed_fp(self):
        # THE RED: a collection failure on a domain closed as a false positive must
        # not put it back in front of an analyst.
        t = self._tok()
        cid = self._ingest("c26-fp.com", "LOW", t)["id"]
        assert self._close(cid, t, "closed_fp") == 200
        out = self._ingest("c26-fp.com", "MEDIUM", t, classification="insufficient_data")
        assert out.get("reopened") is not True
        assert out["status"] == "closed_fp"
        assert self._get(cid, t)["status"] == "closed_fp"

    def test_insufficient_data_does_not_reopen_closed_benign(self):
        # closed_benign is the other disposition that records severity_at_detection
        # and must be equally immune to a collection-failure "escalation".
        t = self._tok()
        cid = self._ingest("c26-benign.com", "LOW", t)["id"]
        assert self._close(cid, t, "closed_benign") == 200
        out = self._ingest("c26-benign.com", "MEDIUM", t, classification="insufficient_data")
        assert out.get("reopened") is not True
        assert out["status"] == "closed_benign"
        assert self._get(cid, t)["status"] == "closed_benign"

    def test_real_escalation_still_reopens_closed_case(self):
        # Non-regression: an actual higher-severity re-classification must keep
        # reopening a closed case exactly as before.
        t = self._tok()
        cid = self._ingest("c26-phish.com", "LOW", t)["id"]
        self._close(cid, t, "closed_fp")
        out = self._ingest("c26-phish.com", "CRITICAL", t, classification="phishing")
        assert out.get("reopened") is True
        assert out["status"] == "new"
        assert out["escalated_from"] == "LOW"
        assert out["escalated_to"] == "CRITICAL"

    def test_needs_review_medium_still_reopens_closed_case(self):
        # The delicate point: a fix that filters on severity == "MEDIUM" instead of
        # on classification would also suppress this legitimate reopen, because
        # needs_review/MEDIUM has the exact same severity as insufficient_data/MEDIUM.
        # Only the classification distinguishes "I looked and it's ambiguous" from
        # "I couldn't look".
        t = self._tok()
        cid = self._ingest("c26-review.com", "LOW", t)["id"]
        self._close(cid, t, "closed_fp")
        out = self._ingest("c26-review.com", "MEDIUM", t, classification="needs_review")
        assert out.get("reopened") is True
        assert out["status"] == "new"
        assert out["escalated_from"] == "LOW"
        assert out["escalated_to"] == "MEDIUM"

    def test_insufficient_data_on_open_case_behaves_as_before(self):
        # Non-regression: an open (not closed) case is untouched by this fix. It
        # keeps refreshing classification/severity on every ingest as it does today.
        t = self._tok()
        cid = self._ingest("c26-open.com", "LOW", t)["id"]
        out = self._ingest("c26-open.com", "MEDIUM", t, classification="insufficient_data")
        assert out["status"] == "new"
        assert out.get("updated") is True
        c = self._get(cid, t)
        assert c["classification"] == "insufficient_data"
        assert c["severity"] == "MEDIUM"

    def test_insufficient_data_does_not_propose_severity_on_locked_closed_case(self):
        # Covers the severity_locked branch of the closed-case path
        # (case_manager.py:592-604): on a closed case whose severity an analyst
        # locked before closure, a collection failure must not even file a pending
        # severity proposal for them to review — there's nothing to review.
        t = self._tok()
        cid = self._ingest("c26-locked.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t), json={"severity": "LOW"})
        self._close(cid, t, "closed_fp")
        out = self._ingest("c26-locked.com", "MEDIUM", t, classification="insufficient_data")
        assert out.get("reopened") is not True
        assert out.get("severity_proposed") is None
        c = self._get(cid, t)
        assert c["status"] == "closed_fp"
        assert c["pending_severity"] is None


class TestManualSeverity:
    """An analyst can override the automatic severity. A manual severity is locked:
    re-scans refresh classification/rationale but must not revert the analyst's rating."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token, classification="parking"):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": "SevTest", "classification": classification,
            "confidence": "low", "severity": severity, "rationale": "auto",
        }).json()

    def _get(self, cid, token):
        return client.get(f"/cases/{cid}", headers=_auth_header(token)).json()["case"]

    def test_set_severity_manually(self):
        t = self._tok()
        cid = self._ingest("sev-set.com", "LOW", t)["id"]
        r = client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                         json={"severity": "HIGH", "reason": "confermato a mano"})
        assert r.status_code == 200
        assert r.json()["locked"] is True
        assert self._get(cid, t)["severity"] == "HIGH"

    def test_rescan_does_not_override_manual_severity(self):
        t = self._tok()
        cid = self._ingest("sev-keep.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                     json={"severity": "HIGH"})
        self._ingest("sev-keep.com", "LOW", t, classification="legitimate_probable")
        c = self._get(cid, t)
        assert c["severity"] == "HIGH"           # analyst rating preserved
        assert c["classification"] == "legitimate_probable"  # rest still refreshed

    def test_release_override_restores_automatic(self):
        t = self._tok()
        cid = self._ingest("sev-auto.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t), json={"severity": "HIGH"})
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t), json={"severity": None})
        self._ingest("sev-auto.com", "LOW", t)
        c = self._get(cid, t)
        assert c["severity"] == "LOW"
        assert not c["severity_locked"]

    def test_invalid_severity_rejected(self):
        t = self._tok()
        cid = self._ingest("sev-bad.com", "LOW", t)["id"]
        r = client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                         json={"severity": "URGENTISSIMO"})
        assert r.status_code == 422

    def test_severity_change_is_audited(self):
        t = self._tok()
        cid = self._ingest("sev-audit.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                     json={"severity": "CRITICAL", "reason": "phishing attivo"})
        hist = client.get(f"/cases/{cid}", headers=_auth_header(t)).json().get("history", [])
        assert any(h["action"] == "severity_changed" for h in hist)


class TestSeverityProposal:
    """When the classifier rates a case HIGHER than the analyst's manual severity it
    must not silently discard the finding: it files a proposal the analyst can approve
    or reject, surfaced in the dashboard."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token, classification="parking"):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": "PropTest", "classification": classification,
            "confidence": "low", "severity": severity, "rationale": "MX su dominio recente",
        }).json()

    def _get(self, cid, token):
        return client.get(f"/cases/{cid}", headers=_auth_header(token)).json()["case"]

    def _lock(self, cid, sev, token):
        return client.patch(f"/cases/{cid}/severity", headers=_auth_header(token),
                            json={"severity": sev})

    def test_higher_classification_files_proposal(self):
        t = self._tok()
        cid = self._ingest("prop-1.com", "MEDIUM", t)["id"]
        self._lock(cid, "LOW", t)
        out = self._ingest("prop-1.com", "HIGH", t, classification="suspicious")
        assert out.get("severity_proposed") == "HIGH"
        c = self._get(cid, t)
        assert c["severity"] == "LOW"            # analyst rating untouched
        assert c["pending_severity"] == "HIGH"   # proposal visible

    def test_lower_classification_files_no_proposal(self):
        t = self._tok()
        cid = self._ingest("prop-2.com", "MEDIUM", t)["id"]
        self._lock(cid, "HIGH", t)
        self._ingest("prop-2.com", "LOW", t)
        assert self._get(cid, t)["pending_severity"] is None

    def test_approve_adopts_proposed_severity(self):
        t = self._tok()
        cid = self._ingest("prop-3.com", "MEDIUM", t)["id"]
        self._lock(cid, "LOW", t)
        self._ingest("prop-3.com", "HIGH", t, classification="suspicious")
        r = client.post(f"/cases/{cid}/severity/proposal", headers=_auth_header(t),
                        json={"action": "approve"})
        assert r.status_code == 200 and r.json()["approved"] is True
        c = self._get(cid, t)
        assert c["severity"] == "HIGH"
        assert c["pending_severity"] is None
        assert c["severity_locked"]  # remains an analyst decision

    def test_reject_keeps_analyst_severity(self):
        t = self._tok()
        cid = self._ingest("prop-4.com", "MEDIUM", t)["id"]
        self._lock(cid, "LOW", t)
        self._ingest("prop-4.com", "HIGH", t, classification="suspicious")
        r = client.post(f"/cases/{cid}/severity/proposal", headers=_auth_header(t),
                        json={"action": "reject"})
        assert r.status_code == 200 and r.json()["approved"] is False
        c = self._get(cid, t)
        assert c["severity"] == "LOW"
        assert c["pending_severity"] is None

    def test_resolve_without_proposal_is_400(self):
        t = self._tok()
        cid = self._ingest("prop-5.com", "MEDIUM", t)["id"]
        r = client.post(f"/cases/{cid}/severity/proposal", headers=_auth_header(t),
                        json={"action": "approve"})
        assert r.status_code == 400

    def test_invalid_action_rejected(self):
        t = self._tok()
        cid = self._ingest("prop-6.com", "MEDIUM", t)["id"]
        r = client.post(f"/cases/{cid}/severity/proposal", headers=_auth_header(t),
                        json={"action": "maybe"})
        assert r.status_code == 422

    def test_proposal_is_audited(self):
        t = self._tok()
        cid = self._ingest("prop-7.com", "MEDIUM", t)["id"]
        self._lock(cid, "LOW", t)
        self._ingest("prop-7.com", "HIGH", t, classification="suspicious")
        client.post(f"/cases/{cid}/severity/proposal", headers=_auth_header(t),
                    json={"action": "approve"})
        hist = client.get(f"/cases/{cid}", headers=_auth_header(t)).json().get("history", [])
        actions = {h["action"] for h in hist}
        assert "severity_proposed" in actions
        assert "severity_proposal_approved" in actions


class TestInputLimitsAndProposalHygiene:
    """Security/robustness hardening: input fields are length-bounded (no unbounded
    writes to the DB), and a manual severity change clears any stale proposal."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token, classification="parking", rationale="x"):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": "LimTest", "classification": classification,
            "confidence": "low", "severity": severity, "rationale": rationale,
        })

    def test_huge_rationale_rejected(self):
        t = self._tok()
        r = self._ingest("lim1.com", "LOW", t, rationale="A" * 100000)
        assert r.status_code == 422

    def test_huge_domain_rejected(self):
        t = self._tok()
        r = self._ingest("A" * 100000 + ".com", "LOW", t)
        assert r.status_code == 422

    def test_huge_severity_reason_rejected(self):
        t = self._tok()
        cid = self._ingest("lim2.com", "MEDIUM", t).json()["id"]
        r = client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                         json={"severity": "HIGH", "reason": "A" * 100000})
        assert r.status_code == 422

    def test_huge_note_rejected(self):
        t = self._tok()
        cid = self._ingest("lim3.com", "MEDIUM", t).json()["id"]
        r = client.post(f"/cases/{cid}/notes", headers=_auth_header(t),
                        json={"note": "A" * 100000})
        assert r.status_code == 422

    def test_normal_inputs_still_accepted(self):
        t = self._tok()
        cid = self._ingest("lim4.com", "MEDIUM", t, rationale="MX forwarding on recent domain").json()["id"]
        assert client.patch(f"/cases/{cid}/severity", headers=_auth_header(t),
                            json={"severity": "HIGH", "reason": "phishing confirmed"}).status_code == 200
        assert client.post(f"/cases/{cid}/notes", headers=_auth_header(t),
                           json={"note": "analyst note"}).status_code == 200

    def test_manual_severity_clears_pending_proposal(self):
        t = self._tok()
        cid = self._ingest("lim5.com", "MEDIUM", t).json()["id"]
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t), json={"severity": "LOW"})
        self._ingest("lim5.com", "HIGH", t, classification="suspicious")  # files a proposal
        # analyst now sets severity by hand → proposal must be cleared
        client.patch(f"/cases/{cid}/severity", headers=_auth_header(t), json={"severity": "MEDIUM"})
        c = client.get(f"/cases/{cid}", headers=_auth_header(t)).json()["case"]
        assert c["pending_severity"] is None


# ═══════════════════════════════════════════
# CODE-05 — /cases `total` must respect filters
# ═══════════════════════════════════════════

class TestCasesFilterTotal:
    """`total` in the /cases response must reflect the same predicates applied to
    the listed rows, not the whole table (BUG-REGISTER CODE-05)."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def test_total_respects_status_filter(self):
        t = self._tok()
        for i in range(3):
            client.post("/cases/ingest", headers=_auth_header(t), json={
                "domain": f"code05-open-{i}.com", "client": "Code05Test", "severity": "LOW"
            })
        cid = client.post("/cases/ingest", headers=_auth_header(t), json={
            "domain": "code05-closed.com", "client": "Code05Test", "severity": "LOW"
        }).json()["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t), json={"status": "closed_tp"})

        resp = client.get("/cases", headers=_auth_header(t),
                          params={"client": "Code05Test", "status": "new"})
        body = resp.json()
        assert body["count"] == 3
        assert body["total"] == 3   # not 4 (the closed one must be excluded from total too)

    def test_total_respects_severity_filter(self):
        t = self._tok()
        client.post("/cases/ingest", headers=_auth_header(t), json={
            "domain": "code05-hi.com", "client": "Code05Sev", "severity": "HIGH"
        })
        client.post("/cases/ingest", headers=_auth_header(t), json={
            "domain": "code05-lo.com", "client": "Code05Sev", "severity": "LOW"
        })
        resp = client.get("/cases", headers=_auth_header(t),
                          params={"client": "Code05Sev", "severity": "HIGH"})
        body = resp.json()
        assert body["count"] == 1
        assert body["total"] == 1  # not 2 (unfiltered count of the client's cases)


# ═══════════════════════════════════════════
# PRC-02 — severity reconciliation at closure
# ═══════════════════════════════════════════

class TestSeverityAtClosure:
    """Closing a case as FP/benign strips its residual severity to INFO — otherwise
    a resolved, no-risk case keeps polluting severity-based backlog filters and
    dashboards forever. The severity observed at detection is preserved in
    `severity_at_detection`, the prerequisite for computing precision per detector
    (BUG-REGISTER PRC-02)."""

    def _tok(self):
        return _login("admin", "admin_password_123").json()["token"]

    def _ingest(self, domain, severity, token, client_name="PRCTest"):
        return client.post("/cases/ingest", headers=_auth_header(token), json={
            "domain": domain, "client": client_name, "classification": "suspicious",
            "confidence": "low", "severity": severity, "rationale": "test",
        }).json()

    def _get(self, cid, token):
        return client.get(f"/cases/{cid}", headers=_auth_header(token)).json()["case"]

    def test_closed_fp_downgrades_to_info_preserving_original(self):
        t = self._tok()
        cid = self._ingest("prc-fp.com", "HIGH", t)["id"]
        r = client.patch(f"/cases/{cid}/status", headers=_auth_header(t),
                         json={"status": "closed_fp"})
        assert r.status_code == 200
        c = self._get(cid, t)
        assert c["severity"] == "INFO"
        assert c["severity_at_detection"] == "HIGH"

    def test_closed_benign_downgrades_to_info_preserving_original(self):
        t = self._tok()
        cid = self._ingest("prc-benign.com", "MEDIUM", t)["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t),
                     json={"status": "closed_benign"})
        c = self._get(cid, t)
        assert c["severity"] == "INFO"
        assert c["severity_at_detection"] == "MEDIUM"

    def test_closed_tp_keeps_original_severity(self):
        # A confirmed true positive is a real incident: its severity is not masked,
        # and severity_at_detection is left unset (severity IS already the value
        # observed at detection for this disposition).
        t = self._tok()
        cid = self._ingest("prc-tp.com", "CRITICAL", t)["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t),
                     json={"status": "closed_tp"})
        c = self._get(cid, t)
        assert c["severity"] == "CRITICAL"
        assert c["severity_at_detection"] is None

    def test_whitelist_action_also_downgrades_to_info(self, monkeypatch):
        # whitelist_case() closes as FP through its own code path (not update_status),
        # and must reconcile severity the same way.
        t = self._tok()
        cid = self._ingest("prc-wl.com", "HIGH", t)["id"]

        class FakeResp:
            ok = True
            status_code = 200

        monkeypatch.setattr("services.case_manager.requests.post", lambda *a, **k: FakeResp())
        r = client.post(f"/cases/{cid}/whitelist", headers=_auth_header(t),
                        json={"reason": "verified legittimo"})
        assert r.status_code == 200
        c = self._get(cid, t)
        assert c["severity"] == "INFO"
        assert c["severity_at_detection"] == "HIGH"

    def test_reopen_restores_severity_for_dashboard_visibility(self):
        # An INFO-downgraded case that comes back into the queue must show its real
        # severity again, otherwise it is invisible to severity-based filters while
        # actively needing triage.
        t = self._tok()
        cid = self._ingest("prc-reopen.com", "HIGH", t)["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t), json={"status": "closed_fp"})
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t), json={"status": "in_progress"})
        c = self._get(cid, t)
        assert c["severity"] == "HIGH"
        assert c["severity_at_detection"] is None

    def test_escalation_uses_severity_at_detection_not_info(self):
        # Regression guard: escalated_from must report the real pre-closure severity,
        # not the INFO placeholder, and the escalation threshold must still be computed
        # against the real value (existing TestClosedCaseEscalation coverage duplicated
        # here with an explicit severity_at_detection check).
        t = self._tok()
        cid = self._ingest("prc-escalate.com", "LOW", t)["id"]
        client.patch(f"/cases/{cid}/status", headers=_auth_header(t), json={"status": "closed_fp"})
        assert self._get(cid, t)["severity_at_detection"] == "LOW"
        out = self._ingest("prc-escalate.com", "HIGH", t)
        assert out.get("reopened") is True
        assert out["escalated_from"] == "LOW"
        assert out["escalated_to"] == "HIGH"


class TestSeverityAtDetectionMigration:
    """Schema migration for severity_at_detection must be idempotent, like the
    existing migrations it is modeled on (case_manager.py:140-153)."""

    def test_migration_is_idempotent_on_db_with_existing_column(self):
        from services import case_manager
        # init_db() already ran once at import time (column exists by now). Running
        # it again must not raise (e.g. sqlite3.OperationalError: duplicate column)
        # and must not re-run the retrofit against already-reconciled data.
        case_manager.init_db()
        case_manager.init_db()

    def test_migration_retrofits_preexisting_closed_cases(self, tmp_path, monkeypatch):
        # Build a DB in the *pre-PRC-02* shape (the exact production case: a
        # closed_fp row whose severity was never reconciled), then run init_db()
        # against it and check the one-time retrofit.
        import sqlite3
        from services import case_manager

        legacy_db = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(legacy_db)
        conn.execute("""
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL, client TEXT NOT NULL,
                classification TEXT, confidence TEXT, severity TEXT,
                status TEXT NOT NULL DEFAULT 'new', assignee_id INTEGER,
                rationale TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                UNIQUE(domain, client)
            )
        """)
        conn.execute(
            "INSERT INTO cases (domain, client, classification, confidence, severity, "
            "status, rationale, created_at, updated_at) VALUES "
            "('legacy-fp.example', 'LegacyClient', 'parking', 'low', 'MEDIUM', "
            "'closed_fp', 'pre-migration case', 't0', 't0')"
        )
        conn.commit()
        conn.close()

        monkeypatch.setattr(case_manager, "DB_PATH", legacy_db)
        case_manager.init_db()          # first run: adds the column, retrofits the row
        case_manager.init_db()          # second run: must be a no-op, not raise

        with sqlite3.connect(legacy_db) as check:
            check.row_factory = sqlite3.Row
            row = check.execute(
                "SELECT severity, severity_at_detection FROM cases WHERE domain='legacy-fp.example'"
            ).fetchone()
        assert row["severity"] == "INFO"
        assert row["severity_at_detection"] == "MEDIUM"
