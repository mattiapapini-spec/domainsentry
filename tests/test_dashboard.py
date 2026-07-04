"""Tests for services/dashboard.py — route serving and asset integrity."""

import os
from fastapi.testclient import TestClient

from services.dashboard import app

client = TestClient(app)


class TestDashboardServing:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["service"] == "dashboard"

    def test_dashboard_served(self):
        r = client.get("/dashboard")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "DomainSentry" in r.text

    def test_no_external_dependencies(self):
        """Critical: the page must not load external resources (locked-down network)."""
        r = client.get("/dashboard")
        html = r.text.lower()
        # No CDN / external script or style references
        assert "http://" not in html.replace("http://www.w3.org", "")  # svg ns is fine
        assert "cdn." not in html
        assert "googleapis" not in html
        assert "unpkg" not in html
        assert "jsdelivr" not in html

    def test_calls_expected_endpoints(self):
        """The page references the case-manager endpoints it depends on."""
        html = client.get("/dashboard").text
        for ep in ["/auth/login", "/auth/me", "/summary", "/cases",
                   "/users/assignable", "/whitelist", "/assign", "/notes", "/status", "/intel",
                   "/trigger", "/feed/clients", "/feed/clients/onboard", "/feed/domains/promote", "/progress"]:
            assert ep in html, f"dashboard missing reference to {ep}"

    def test_intel_tabs_present(self):
        """The drawer has Overview / Intelligence / Raw JSON tabs."""
        html = client.get("/dashboard").text
        assert "renderIntelTab" in html
        assert "renderRawTab" in html
        assert "switchTab" in html
        assert "Baseline diff history" in html

    def test_permission_gating_present(self):
        """Action buttons are gated by permission checks in the JS."""
        html = client.get("/dashboard").text
        for perm in ["manage_cases", "assign_cases", "whitelist", "add_notes"]:
            assert perm in html


class TestDashboardNoUndeclaredGlobals:
    """
    Regression: rewrites of the dashboard JS dropped `let viewAssignee` and
    `const VIEW_TITLES`, causing a ReferenceError that left the case table blank
    while the summary cards still rendered. Guard that the state globals used by
    the load/render path are actually declared.
    """
    def test_state_globals_declared(self):
        import re
        html = client.get("/dashboard").text
        script = html[html.rfind("<script>"):]
        declared = set(re.findall(r'\b(?:let|const|var)\s+([A-Za-z_$][\w$]*)', script))
        for name in ["TOKEN", "ME", "ASSIGNABLE", "CURRENT", "VIEW", "viewAssignee",
                     "VIEW_TITLES", "CURRENT_INTEL", "OB_DOMAINS", "DOMAIN_RE"]:
            assert name in declared, f"global '{name}' is used but never declared (ReferenceError risk)"
