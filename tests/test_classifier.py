"""Tests for services/classifier.py auto-classification rules."""

import pytest
import json
from fastapi.testclient import TestClient
from services.classifier import app

client = TestClient(app)


class TestClassifyVariant:
    """Test auto-classification rules."""

    def _classify(self, domain, dns=None, http=None, cert=None, **kwargs):
        body = {"domain": domain, "fuzzer": kwargs.get("fuzzer", "test"), 
                "dns": dns, "http": http, "cert": cert}
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200
        return resp.json()

    def test_parking_minimal_content(self):
        """HTTP 200 with <200 bytes → parking."""
        result = self._classify("parked.com", http={
            "checks": [{"status_code": 200, "content_length": 95}],
            "overall_status": "active"
        })
        assert result["auto_classification"] == "parking"
        assert result["confidence"] == "high"

    def test_parking_known_ns(self):
        """Known parking nameservers → parking."""
        result = self._classify("parked.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}
        })
        assert result["auto_classification"] == "parking"

    def test_parking_known_ip(self):
        """Known parking IPs → parking."""
        result = self._classify("parked.com", dns={
            "records": {"A": ["15.197.148.33"], "MX": [], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "parking"

    def test_for_sale_marketplace_ns(self):
        """Marketplace nameservers → for_sale."""
        result = self._classify("forsale.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.brandbucket.com"]}
        })
        assert result["auto_classification"] == "for_sale"

    def test_for_sale_parking_mx(self):
        """Parking MX → for_sale."""
        result = self._classify("forsale.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["park-mx.above.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "for_sale"

    def test_legitimate_enterprise_cert(self):
        """Enterprise cert provider → legitimate_probable."""
        result = self._classify("legit.com", cert={
            "ct_certificates": {"total": 5, "unique_cn": ["tls.automattic.com", "legit.com"]}
        }, dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}})
        assert result["auto_classification"] == "legitimate_probable"

    def test_legitimate_substantial_content(self):
        """HTTP active with >3KB content → legitimate_probable."""
        result = self._classify("legit.com", 
            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
            http={"checks": [{"status_code": 200, "content_length": 45000}], "overall_status": "active"})
        assert result["auto_classification"] == "legitimate_probable"

    def test_suspicious_mx_only(self):
        """MX active without A record → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": [], "MX": ["10 mx.zoho.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"
        assert result["action"] == "block_and_monitor"

    def test_suspicious_privacy_mx(self):
        """ProtonMail MX → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["mail.protonmail.ch"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"

    def test_suspicious_forwarding_mx(self):
        """Namecheap email forwarding → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["eforward1.registrar-servers.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"

    def test_suspicious_hidden_elements(self):
        """High risk hidden elements → suspicious."""
        result = self._classify("suspicious.com",
            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
            http={"checks": [{"status_code": 200, "content_length": 5000,
                "hidden_elements": {"risk_indicators": 35, "summary": ["hidden form detected"]}}],
                "overall_status": "active"})
        assert result["auto_classification"] == "suspicious"

    def test_needs_review_fallback(self):
        """No matching rule → needs_review."""
        result = self._classify("unknown.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["mx.unknown-provider.com"], "NS": ["ns1.unknown.com"]}
        })
        assert result["auto_classification"] == "needs_review"

    def test_empty_input(self):
        """No data at all → needs_review."""
        result = self._classify("empty.com")
        assert result["auto_classification"] == "needs_review"

    def test_none_content_length_no_crash(self):
        """content_length=None should not crash max()."""
        result = self._classify("test.com", 
            dns={"records": {"A": [], "MX": [], "NS": []}},
            http={"checks": [{"status_code": None, "content_length": None}], "overall_status": "down"})
        # Should not raise TypeError
        assert result["auto_classification"] == "needs_review"


class TestClassifyBatch:
    def test_batch_classification(self):
        resp = client.post("/classify/batch", json={
            "variants": [
                {"domain": "parked.com", "fuzzer": "test", "http": {
                    "checks": [{"status_code": 200, "content_length": 50}], "overall_status": "active"}},
                {"domain": "suspicious.com", "fuzzer": "test", "dns": {
                    "records": {"A": [], "MX": ["mail.protonmail.ch"], "NS": []}}},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["summary"]["parking"] == 1
        assert data["summary"]["suspicious"] == 1


class TestHealth:
    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
