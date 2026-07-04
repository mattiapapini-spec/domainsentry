"""Tests for shared/auth.py and services/case_manager.py"""

import os
import tempfile
import pytest

# Use a temp DB before importing the service
_tmpdir = tempfile.mkdtemp()
os.environ["CASES_DB"] = os.path.join(_tmpdir, "test_cases.db")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "admin_password_123"

from shared.auth import (hash_password, verify_password, generate_token,
                         hash_token, permissions_for_role, ROLE_PRESETS)
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
