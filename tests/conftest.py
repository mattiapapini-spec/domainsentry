"""Shared test fixtures."""

import pytest


@pytest.fixture
def sample_dns_result():
    return {
        "domain": "example.com",
        "records": {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 -all"],
        },
        "email_auth": {
            "spf": {"present": True, "records": ["v=spf1 -all"], "policy": "fail"},
            "dmarc": {"present": False, "records": []},
            "dkim": {"selectors_found": [], "selectors_tested": 17, "records": {}},
        }
    }


@pytest.fixture
def sample_http_parking():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 95,
             "hidden_elements": {"risk_indicators": 0, "summary": []}},
        ],
        "overall_status": "active"
    }


@pytest.fixture
def sample_http_real_site():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 45000,
             "hidden_elements": {"risk_indicators": 0, "summary": []}},
        ],
        "overall_status": "active"
    }


@pytest.fixture
def sample_http_suspicious():
    return {
        "checks": [
            {"url": "http://example.com", "status_code": 200, "content_length": 5000,
             "hidden_elements": {
                 "hidden_forms": [{"action": "https://evil.com/steal.php"}],
                 "risk_indicators": 35,
                 "summary": ["1 form nascosti — possibile credential harvesting"]
             }},
        ],
        "overall_status": "active"
    }
