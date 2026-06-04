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
