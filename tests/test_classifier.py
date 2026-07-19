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


# ═══════════════════════════════════════════
# REGRESSION: /diff crash on None-valued intel keys
# ═══════════════════════════════════════════

class TestDiffNoneSafety:
    """
    A stored snapshot can have a key PRESENT with value None (e.g. "cert": null
    when a domain has no certificates). baseline_diff must not crash on these.
    Reproduces the kedrionta.com HTTP 500 found in production.
    """

    def _mk(self, **over):
        base = {
            "dns": {"records": {"A": ["1.2.3.4"]}, "email_auth": {}},
            "cert": None, "http": None, "whois": None, "reputation": None,
        }
        base.update(over)
        return base

    def test_diff_survives_none_cert(self):
        from services.classifier import baseline_diff, DiffInput
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com",
                                    baseline=self._mk(), current=self._mk()))
        assert r.status_code == 200

    def test_diff_survives_all_none_sections(self):
        from services.classifier import baseline_diff, DiffInput
        # every optional section None on both sides
        allnone = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com",
                                    baseline=allnone, current=allnone))
        assert r.status_code == 200

    def test_diff_detects_changes_from_none_baseline(self):
        """Going from None sections to populated ones should still detect changes."""
        import json
        from services.classifier import baseline_diff, DiffInput
        prev = {"dns": {"records": {"A": []}, "email_auth": {"spf": {"present": False}}},
                "cert": None, "http": None, "whois": None, "reputation": None}
        curr = {"dns": {"records": {"A": ["9.9.9.9"], "MX": ["10 m.x"]}, "email_auth": {"spf": {"present": True, "records": ["v=spf1 ~all"]}}},
                "cert": {"ct_certificates": {"total": 3}}, "http": {"checks": [{"url": "http://x.com", "status_code": 200}]},
                "whois": None, "reputation": None}
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com", baseline=prev, current=curr))
        assert r.status_code == 200
        body = json.loads(r.body)
        types = {a["type"] for a in body["alerts"]}
        assert "mx_record_changed" in types
        assert "http_activated" in types


class TestDomainAgeRule:
    """Point 1: domain-age classification. An old, inert domain that predates a
    campaign is likely a legitimate third party; but a recent domain with MX (even
    with a facade website) must stay flagged, and an old domain re-registered
    recently must NOT be auto-cleared."""

    def _classify(self, domain, whois=None, dns=None, http=None, cert=None):
        from services.classifier import classify_variant, VariantInput
        import json
        vi = VariantInput(domain=domain, whois=whois or {}, dns=dns or {},
                          http=http or {}, cert=cert or {})
        return json.loads(classify_variant(vi).body)

    def test_old_inert_domain_is_third_party(self):
        r = self._classify("kedrlon.com",
                            whois={"creation_date": "2019-10-09T00:00:00"},
                            dns={"records": {"A": ["1.2.3.4"]}})
        assert r["auto_classification"] == "likely_third_party"
        assert r["confidence"] == "low"

    def test_recent_domain_with_mx_stays_suspicious(self):
        # facade site + MX on a recent domain must NOT be cleared as legitimate
        r = self._classify("daniei-fake.com",
                            whois={"creation_date": "2025-10-18T00:00:00"},
                            dns={"records": {"A": ["1.2.3.4"], "MX": ["10 eforward1.registrar-servers.com"]}},
                            http={"checks": [{"status_code": 200, "content_length": 8000}]})
        assert r["auto_classification"] == "suspicious"

    def test_old_domain_recently_reregistered_needs_review(self):
        # created long ago but updated recently → possible drop-catch, don't clear
        from datetime import datetime, timedelta
        recent = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00")
        r = self._classify("dropcatch.com",
                            whois={"creation_date": "2010-01-01T00:00:00", "updated_date": recent},
                            dns={"records": {"A": ["1.2.3.4"]}})
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "old_domain_recently_updated"

    def test_recent_inert_domain_still_needs_review(self):
        # recent, no records worth a rule → stays needs_review (not auto-cleared)
        r = self._classify("newthing.com",
                            whois={"creation_date": "2026-05-01T00:00:00"},
                            dns={"records": {}})
        assert r["auto_classification"] == "needs_review"


class TestClassifierRobustness:
    """Bug hunt findings: the classifier must not crash on malformed/partial input
    (WHOIS list-dates, future dates, None sub-objects) which occur with real data."""

    def _post(self, payload):
        return client.post("/classify/variant", json=payload)

    def test_whois_list_date_handled(self):
        # python-whois often returns creation_date as a LIST — must use earliest
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": ["2019-10-09", "2019-10-10"]})
        assert r["age_days"] is not None
        assert r["created"] == "2019-10-09"

    def test_future_creation_date_clamped(self):
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2050-01-01T00:00:00"})
        assert r["age_days"] is None  # not a negative number

    def test_none_records_no_crash(self):
        assert self._post({"domain": "x.com", "dns": {"records": None}}).status_code == 200

    def test_none_checks_no_crash(self):
        assert self._post({"domain": "x.com", "http": {"checks": None}}).status_code == 200

    def test_none_in_checks_list_no_crash(self):
        assert self._post({"domain": "x.com", "http": {"checks": [None]}}).status_code == 200

    def test_none_cert_certificates_no_crash(self):
        assert self._post({"domain": "x.com", "cert": {"ct_certificates": None}}).status_code == 200

    def test_all_none_sub_objects(self):
        r = self._post({"domain": "x.com", "dns": None, "http": None,
                        "cert": None, "whois": None})
        assert r.status_code == 200
        assert "auto_classification" in r.json()


class TestClassifierSecurity:
    """Security audit: WHOIS data is attacker-controlled (registrant sets their own
    record). Parsing it must resist DoS, log injection, and type confusion."""

    def test_huge_list_no_dos(self):
        # a hostile WHOIS returning a giant date list must be bounded
        import time
        from services.classifier import _domain_age
        t0 = time.time()
        r = _domain_age({"creation_date": ["2019-01-01"] * 100000})
        assert (time.time() - t0) < 0.2  # bounded, not O(n) over 100k
        assert r["created"] == "2019-01-01"

    def test_huge_string_no_dos(self):
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2019-" + "0" * 100000})
        assert r["age_days"] is None  # junk, safely rejected

    def test_newline_not_in_output(self):
        # log-injection payload in a date must never reach the formatted output
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2019-01-01\n\n\nFAKE LOG LINE"})
        assert r["created"] == "2019-01-01"
        assert "\n" not in (r["created"] or "")

    def test_non_string_date_types_rejected(self):
        from services.classifier import _domain_age
        for bad in [{"evil": "x"}, b"2019-01-01", [["2019"]], 10**100]:
            r = _domain_age({"creation_date": bad})
            assert r["age_days"] is None

    def test_batch_size_capped(self):
        big = {"variants": [{"domain": f"d{i}.com"} for i in range(1001)]}
        assert client.post("/classify/batch", json=big).status_code == 422


class TestAgeModulatedSeverity:
    """Weak threat signals (hidden elements, MX-only, forwarding/privacy MX) are normal on
    long-established third-party domains. They must alarm only on recent registrations,
    otherwise the HIGH bucket fills with decades-old legitimate businesses."""

    def _classify(self, domain, whois=None, dns=None, http=None, cert=None):
        from services.classifier import classify_variant, VariantInput
        import json
        vi = VariantInput(domain=domain, whois=whois or {}, dns=dns or {},
                          http=http or {}, cert=cert or {})
        return json.loads(classify_variant(vi).body)

    def _hidden(self, risk=45):
        return {"checks": [{"status_code": 200, "content_length": 5000,
                            "hidden_elements": {"risk_indicators": risk,
                                                "summary": ["1 iframe invisibili"]}}]}

    def test_hidden_elements_on_old_domain_is_not_high(self):
        r = self._classify("comad-example.it",
                           whois={"creation_date": "2000-10-18T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "hidden_elements_aged_domain"

    def test_hidden_elements_on_recent_domain_is_high(self):
        r = self._classify("newfake.com",
                           whois={"creation_date": "2026-03-01T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] == "suspicious"
        assert r["rule"] == "hidden_elements_detected"

    def test_mx_only_on_old_domain_is_not_high(self):
        # a decades-old email-only domain is a normal small business
        r = self._classify("conod-example.it",
                           whois={"creation_date": "2008-09-19T00:00:00"},
                           dns={"records": {"MX": ["10 mxb1.fastweb.it"]}})
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "mx_only_aged_domain"

    def test_mx_only_on_recent_domain_is_high(self):
        r = self._classify("armed.com",
                           whois={"creation_date": "2026-01-03T00:00:00"},
                           dns={"records": {"MX": ["10 armed-com.mail.protection.outlook.com"]}})
        assert r["auto_classification"] == "suspicious"
        assert r["rule"] == "mx_only_no_web"

    def test_renewal_does_not_escalate_old_domain(self):
        # WHOIS updated_date changes on routine renewal: it must not push an old domain
        # back into HIGH, only prevent auto-clearing to LOW
        from datetime import datetime, timedelta
        recent = (datetime.utcnow() - timedelta(days=20)).strftime("%Y-%m-%dT00:00:00")
        r = self._classify("renewed.it",
                           whois={"creation_date": "2001-01-01T00:00:00", "updated_date": recent},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] != "suspicious"

    def test_recent_inert_domain_gets_explicit_rule(self):
        r = self._classify("dormant.com",
                           whois={"creation_date": "2026-05-13T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}})
        assert r["rule"] == "recent_registration_inactive"
        assert r["auto_classification"] == "needs_review"
