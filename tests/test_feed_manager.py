"""Tests for services/feed_manager.py — including security tests."""

import pytest
from fastapi.testclient import TestClient

# Override data dir before import
import os
os.environ["FEED_DATA"] = "/tmp/test_feed_data"

from services.feed_manager import app, _safe_client_name

client = TestClient(app)


class TestSafeClientName:
    """Path traversal protection tests."""

    def test_valid_name(self):
        assert _safe_client_name("acmecorp") == "acmecorp"

    def test_valid_with_hyphen(self):
        assert _safe_client_name("my-client") == "my-client"

    def test_valid_with_underscore(self):
        assert _safe_client_name("my_client") == "my_client"

    def test_path_traversal_dots(self):
        with pytest.raises(Exception):  # HTTPException
            _safe_client_name("../../etc")

    def test_path_traversal_slash(self):
        with pytest.raises(Exception):
            _safe_client_name("client/../../passwd")

    def test_empty_name(self):
        with pytest.raises(Exception):
            _safe_client_name("")

    def test_special_chars(self):
        with pytest.raises(Exception):
            _safe_client_name("client@evil")


class TestFeedDomains:
    def test_add_and_list(self):
        import time
        unique = f"test-{int(time.time())}.com"
        # Add
        resp = client.post("/feed/domains", json={
            "domain": unique, "client": "testclient",
            "legitimate": "test.com", "type": "target"
        })
        assert resp.status_code == 200

        # List
        resp = client.get("/feed/domains?client=testclient")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        domains = [d["domain"] for d in data["domains"]]
        assert unique in domains

    def test_add_duplicate_rejected(self):
        import time
        unique = f"dup-{int(time.time())}.com"
        client.post("/feed/domains", json={
            "domain": unique, "client": "testclient",
            "legitimate": "test.com"
        })
        resp = client.post("/feed/domains", json={
            "domain": unique, "client": "testclient",
            "legitimate": "test.com"
        })
        assert resp.status_code == 400

    def test_remove_domain(self):
        import time
        unique = f"remove-{int(time.time())}.com"
        client.post("/feed/domains", json={
            "domain": unique, "client": "testclient",
            "legitimate": "test.com"
        })
        resp = client.delete(f"/feed/domains/{unique}?client=testclient")
        assert resp.status_code == 200

    def test_remove_nonexistent(self):
        resp = client.delete("/feed/domains/doesnotexist.com")
        assert resp.status_code == 404


class TestWhitelist:
    def test_add_and_get(self):
        resp = client.post("/feed/whitelist?client=testclient", json={
            "domain": "legit.com", "reason": "Verified business"
        })
        assert resp.status_code == 200

        resp = client.get("/feed/whitelist?client=testclient")
        assert resp.status_code == 200
        assert "legit.com" in resp.json()["whitelist"]

    def test_remove_whitelist(self):
        client.post("/feed/whitelist?client=testclient", json={
            "domain": "temp-legit.com", "reason": "Test"
        })
        resp = client.delete("/feed/whitelist/temp-legit.com?client=testclient")
        assert resp.status_code == 200

    def test_whitelist_path_traversal(self):
        """Attempting path traversal via client name should be rejected."""
        resp = client.get("/feed/whitelist?client=../../etc")
        assert resp.status_code == 400


class TestHealth:
    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200


# ═══════════════════════════════════════════
# WRITE AUTH (FEED_REQUIRE_AUTH)
# ═══════════════════════════════════════════

class TestFeedWriteAuth:
    """
    Auth layer on write endpoints. The feed-manager validates bearer tokens
    against the case-manager via shared.auth.verify_token_remote, which we
    patch here so the tests run standalone.
    """

    def _reload_with_auth(self, monkeypatch, enabled):
        """Reload feed_manager with FEED_REQUIRE_AUTH toggled."""
        import importlib
        monkeypatch.setenv("FEED_REQUIRE_AUTH", "true" if enabled else "false")
        monkeypatch.setenv("FEED_DATA", "/tmp/test_feed_auth")
        import services.feed_manager as fm
        importlib.reload(fm)
        return fm

    def test_auth_disabled_write_open(self, monkeypatch):
        """Default behaviour: no auth required, writes succeed without token."""
        fm = self._reload_with_auth(monkeypatch, enabled=False)
        c = TestClient(fm.app)
        r = c.post("/feed/domains", json={
            "domain": "noauth.com", "client": "acme", "legitimate": "acme.com"
        })
        assert r.status_code == 200

    def test_auth_enabled_no_token_rejected(self, monkeypatch):
        """Auth enabled: write without token → 401."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        c = TestClient(fm.app)
        r = c.post("/feed/domains", json={
            "domain": "needauth.com", "client": "acme", "legitimate": "acme.com"
        })
        assert r.status_code == 401

    def test_auth_enabled_valid_token_with_permission(self, monkeypatch):
        """Auth enabled: valid token holding the permission → write succeeds."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        # Patch token introspection to return a user with manage_cases
        monkeypatch.setattr(fm, "verify_token_remote",
                            lambda token, url, **kw: {
                                "id": 2, "username": "analyst1", "role": "analyst",
                                "permissions": ["manage_cases", "whitelist", "view"]
                            })
        c = TestClient(fm.app)
        r = c.post("/feed/domains",
                   headers={"Authorization": "Bearer validtoken"},
                   json={"domain": "authed.com", "client": "acme", "legitimate": "acme.com"})
        assert r.status_code == 200

    def test_auth_enabled_token_without_permission(self, monkeypatch):
        """Auth enabled: valid token lacking the permission → 403."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        # Viewer: only 'view', no manage_cases
        monkeypatch.setattr(fm, "verify_token_remote",
                            lambda token, url, **kw: {
                                "id": 3, "username": "viewer1", "role": "viewer",
                                "permissions": ["view"]
                            })
        c = TestClient(fm.app)
        r = c.post("/feed/domains",
                   headers={"Authorization": "Bearer viewertoken"},
                   json={"domain": "forbidden.com", "client": "acme", "legitimate": "acme.com"})
        assert r.status_code == 403

    def test_auth_enabled_invalid_token(self, monkeypatch):
        """Auth enabled: token that fails introspection → 401."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        monkeypatch.setattr(fm, "verify_token_remote", lambda token, url, **kw: None)
        c = TestClient(fm.app)
        r = c.post("/feed/domains",
                   headers={"Authorization": "Bearer badtoken"},
                   json={"domain": "bad.com", "client": "acme", "legitimate": "acme.com"})
        assert r.status_code == 401

    def test_auth_enabled_reads_still_open(self, monkeypatch):
        """Auth enabled: GET endpoints remain open (writes-only protection)."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        c = TestClient(fm.app)
        r = c.get("/feed/domains?client=acme")
        assert r.status_code == 200

    def test_whitelist_requires_whitelist_permission(self, monkeypatch):
        """Whitelist write needs the 'whitelist' permission specifically."""
        fm = self._reload_with_auth(monkeypatch, enabled=True)
        # User has manage_cases but NOT whitelist
        monkeypatch.setattr(fm, "verify_token_remote",
                            lambda token, url, **kw: {
                                "id": 4, "username": "analyst2", "role": "analyst",
                                "permissions": ["manage_cases", "view"]
                            })
        c = TestClient(fm.app)
        r = c.post("/feed/whitelist?client=acme",
                   headers={"Authorization": "Bearer t"},
                   json={"domain": "wl.com", "reason": "test"})
        assert r.status_code == 403


def teardown_module(module):
    """Restore default (no-auth) feed_manager for other test modules."""
    import importlib, os
    os.environ["FEED_REQUIRE_AUTH"] = "false"
    os.environ["FEED_DATA"] = "/tmp/test_feed_data"
    import services.feed_manager as fm
    importlib.reload(fm)


# ═══════════════════════════════════════════
# CLIENT ONBOARDING (bulk domains + notes)
# ═══════════════════════════════════════════

class TestClientOnboard:
    def _client(self, monkeypatch, tmp_path):
        import importlib
        monkeypatch.setenv("FEED_FILE", str(tmp_path / "feed_ob.json"))
        monkeypatch.setenv("FEED_REQUIRE_AUTH", "false")
        import services.feed_manager as fm
        importlib.reload(fm)
        return TestClient(fm.app)

    def test_onboard_adds_domains_and_notes(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/clients/onboard", json={
            "client": "acme", "legitimate": "acme.com", "notes": "pharma client",
            "domains": [{"domain": "acrne.com", "type": "target"},
                        {"domain": "acme-login.com", "type": "watchlist"}],
        })
        assert r.status_code == 200
        b = r.json()
        assert b["added_count"] == 2
        # listing reflects it with notes + correct buckets
        cl = c.get("/feed/clients").json()
        acme = [x for x in cl["clients"] if x["name"] == "acme"][0]
        assert acme["targets"] == ["acrne.com"]
        assert acme["watchlist"] == ["acme-login.com"]
        assert acme["notes"] == "pharma client"

    def test_onboard_skips_invalid_and_duplicates(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/clients/onboard", json={
            "client": "acme", "legitimate": "acme.com",
            "domains": [{"domain": "good.com"}, {"domain": "good.com"},
                        {"domain": "not a domain"}],
        })
        b = r.json()
        assert b["added_count"] == 1
        assert b["skipped_count"] == 2

    def test_onboard_rejects_bad_client_name(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/clients/onboard", json={
            "client": "acme inc!", "legitimate": "acme.com", "domains": [],
        })
        assert r.status_code == 422

    def test_onboard_rejects_bad_legitimate(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/clients/onboard", json={
            "client": "acme", "legitimate": "notadomain", "domains": [],
        })
        assert r.status_code == 422


class TestPromoteDomain:
    """Promote a dnstwist variant (or add by hand) to a monitored target,
    resolving the client's legitimate domain automatically."""
    def _client(self, monkeypatch, tmp_path):
        import importlib
        monkeypatch.setenv("FEED_FILE", str(tmp_path / "feed_pr.json"))
        monkeypatch.setenv("FEED_REQUIRE_AUTH", "false")
        import services.feed_manager as fm
        importlib.reload(fm)
        c = TestClient(fm.app)
        c.post("/feed/clients/onboard", json={"client": "kedrion", "legitimate": "kedrion.com",
                                              "domains": [{"domain": "kerdion.com"}]})
        return c

    def test_promote_resolves_legitimate(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/domains/promote", json={"domain": "medrion.com", "client": "kedrion"})
        assert r.status_code == 200
        assert r.json()["legitimate"] == "kedrion.com"
        cl = c.get("/feed/clients").json()
        k = [x for x in cl["clients"] if x["name"] == "kedrion"][0]
        assert "medrion.com" in k["targets"]

    def test_promote_unknown_client_404(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/domains/promote", json={"domain": "x.com", "client": "ghost"})
        assert r.status_code == 404

    def test_promote_duplicate_400(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        c.post("/feed/domains/promote", json={"domain": "medrion.com", "client": "kedrion"})
        r = c.post("/feed/domains/promote", json={"domain": "medrion.com", "client": "kedrion"})
        assert r.status_code == 400

    def test_promote_invalid_domain_422(self, monkeypatch, tmp_path):
        c = self._client(monkeypatch, tmp_path)
        r = c.post("/feed/domains/promote", json={"domain": "not a domain", "client": "kedrion"})
        assert r.status_code == 422
