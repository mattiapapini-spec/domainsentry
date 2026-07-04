"""Tests for shared/utils.py"""

import pytest
from shared.utils import (
    is_valid, content_hash, normalize_html_for_fingerprint,
    extract_visible_text, detect_suspicious_patterns,
    detect_hidden_elements, now_iso, is_check_due,
)


class TestIsValid:
    def test_valid_records(self):
        assert is_valid(["93.184.216.34"]) is True

    def test_empty_list(self):
        assert is_valid([]) is False

    def test_empty_string(self):
        assert is_valid([""]) is False

    def test_error_message(self):
        assert is_valid(["ERROR: timeout"]) is False

    def test_multiple_records(self):
        assert is_valid(["1.2.3.4", "5.6.7.8"]) is True


class TestContentHash:
    def test_string_input(self):
        h = content_hash("hello")
        assert len(h) == 64  # sha256 hex

    def test_bytes_input(self):
        h = content_hash(b"hello")
        assert len(h) == 64

    def test_deterministic(self):
        assert content_hash("test") == content_hash("test")

    def test_different_input(self):
        assert content_hash("a") != content_hash("b")


class TestNormalizeHtml:
    def test_removes_scripts(self):
        html = '<p>Hello</p><script>alert(1)</script><p>World</p>'
        result = normalize_html_for_fingerprint(html)
        assert "alert" not in result
        assert "Hello" in result

    def test_removes_styles(self):
        html = '<style>body{color:red}</style><p>Text</p>'
        result = normalize_html_for_fingerprint(html)
        assert "color:red" not in result

    def test_removes_timestamps(self):
        html = '<p>Generated 1714200000000</p>'
        result = normalize_html_for_fingerprint(html)
        assert "1714200000000" not in result

    def test_removes_hashes(self):
        html = '<p>Token: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4</p>'
        result = normalize_html_for_fingerprint(html)
        assert "a1b2c3d4e5f6" not in result

    def test_collapses_whitespace(self):
        html = '<p>  lots   of    space  </p>'
        result = normalize_html_for_fingerprint(html)
        assert "  " not in result


class TestExtractVisibleText:
    def test_strips_tags(self):
        html = '<div><p>Hello <b>World</b></p></div>'
        assert "Hello" in extract_visible_text(html)
        assert "<div>" not in extract_visible_text(html)

    def test_strips_scripts(self):
        html = '<p>Visible</p><script>hidden()</script>'
        text = extract_visible_text(html)
        assert "Visible" in text
        assert "hidden" not in text


class TestDetectSuspiciousPatterns:
    def test_detects_password_field(self):
        html = '<input type="password" name="pwd">'
        findings = detect_suspicious_patterns(html, [r"password|passwd|pwd"])
        assert len(findings) > 0

    def test_no_false_positive(self):
        html = '<p>Welcome to our website</p>'
        findings = detect_suspicious_patterns(html, [r"password|passwd|pwd"])
        assert len(findings) == 0

    def test_invalid_regex_handled(self):
        html = '<p>test</p>'
        findings = detect_suspicious_patterns(html, [r"[invalid"])
        assert len(findings) == 0


class TestDetectHiddenElements:
    def test_hidden_form(self):
        html = '<form style="display:none" action="https://evil.com/steal.php"><input type="text"></form>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_invisible_iframe_zero_size(self):
        html = '<iframe src="https://evil.com" width="0" height="0"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        assert result["risk_indicators"] >= 25

    def test_invisible_iframe_css(self):
        html = '<iframe src="https://evil.com" style="display:none"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")

    def test_tracking_pixel(self):
        html = '<img src="https://tracker.com/px.gif" width="1" height="1">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")

    def test_meta_redirect(self):
        html = '<meta http-equiv="refresh" content="0;url=https://phishing.com">'
        result = detect_hidden_elements(html)
        assert result.get("meta_redirects")
        assert result["meta_redirects"][0]["target_url"] == "https://phishing.com"

    def test_obfuscated_js_eval(self):
        html = '<script>eval(atob("YWxlcnQoMSk="))</script>'
        result = detect_hidden_elements(html)
        assert result.get("obfuscated_js")
        indicators = result["obfuscated_js"][0]["indicators"]
        assert "eval" in indicators
        assert "atob_base64" in indicators

    def test_hidden_div_with_form(self):
        html = '<div style="display:none"><form action="/login"><input type="password">This is a hidden credential form</form></div>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_divs_with_content")
        assert result["hidden_divs_with_content"][0]["contains_form"] is True

    def test_large_comment_with_code(self):
        html = '<!-- <script>function steal(){document.cookie}</script>' + 'x' * 200 + ' -->'
        result = detect_hidden_elements(html)
        assert result.get("large_comments")
        assert result["large_comments"][0]["contains_javascript"] is True

    def test_clean_page(self):
        html = '<html><head><title>Hello</title></head><body><p>Clean page</p></body></html>'
        result = detect_hidden_elements(html)
        assert result["risk_indicators"] == 0

    def test_legitimate_hidden_input(self):
        """A single hidden input (CSRF token) should not trigger high risk."""
        html = '<form><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="search"></form>'
        result = detect_hidden_elements(html)
        # Should have hidden_inputs but risk should be low (<=3 hidden inputs)
        assert result.get("hidden_inputs")
        assert result["risk_indicators"] < 15


class TestTimeHelpers:
    def test_now_iso_format(self):
        ts = now_iso()
        assert "T" in ts
        assert "+" in ts or "Z" in ts

    def test_is_check_due_none(self):
        assert is_check_due(None, 24) is True

    def test_is_check_due_recent(self):
        assert is_check_due(now_iso(), 24) is False

    def test_is_check_due_old(self):
        assert is_check_due("2020-01-01T00:00:00+00:00", 24) is True

    def test_is_check_due_invalid(self):
        assert is_check_due("not-a-date", 24) is True


class TestHiddenElementsFalsePositives:
    """
    Regression: the classifier flagged legitimate sites (millewin.it — a real
    WordPress app with a login area) as CRITICAL "compromise/credential kit".
    Causes: (1) wp-emoji \\uXXXX sequences marked as obfuscated JS, (2) the site's
    own /wp-content/ resources counted as external, (3) any login text = alert.
    Fix must clear these FPs WITHOUT creating false negatives on real phishing.
    """
    from shared.utils import detect_hidden_elements as _d

    def test_wp_emoji_unicode_not_flagged_as_obfuscated(self):
        from shared.utils import detect_hidden_elements
        html = ('<script>const a=JSON.parse(document.getElementById("wp-emoji-settings").textContent);'
                'var e="\\u1f600\\u1f601\\u1f602\\u1f603\\u1f604\\u1f605\\u1f606\\u1f607\\u1f608\\u1f609'
                '\\u1f60a\\u1f60b\\u1f60c\\u1f60d\\u1f60e";</script>')
        r = detect_hidden_elements(html, self_domain="millewin.it")
        # unicode escapes alone (no eval/atob/etc) must NOT count as obfuscation
        assert len(r.get("obfuscated_js", [])) == 0

    def test_self_hosted_resources_not_external(self):
        from shared.utils import detect_hidden_elements
        html = ('<link href="https://millewin.it/wp-content/themes/x/style.css">'
                '<script src="https://millewin.it/wp-includes/js/jquery.js"></script>'
                '<a href="https://download.millewin.it/files/tool.exe">dl</a>')
        r = detect_hidden_elements(html, self_domain="millewin.it")
        ext = r.get("external_resources", [])
        assert not any("millewin.it" in u for u in ext)

    def test_real_obfuscation_still_detected(self):
        from shared.utils import detect_hidden_elements
        html = ('<script>eval(atob("dmFy"));document.write(unescape("%3C"));'
                'var x=String.fromCharCode(104,116);</script>')
        r = detect_hidden_elements(html, self_domain="evil.com")
        # genuine obfuscation (eval/atob/document_write/fromCharCode) MUST be flagged
        assert len(r.get("obfuscated_js", [])) >= 1

    def test_real_external_malicious_still_detected(self):
        from shared.utils import detect_hidden_elements
        html = ('<script src="https://evil-exfil.ru/c.js"></script>'
                '<form action="https://evil-exfil.ru/steal.php"></form>')
        r = detect_hidden_elements(html, self_domain="kerdion-fake.com")
        ext = r.get("external_resources", [])
        assert any("evil-exfil.ru" in u for u in ext)


class TestSSRFProtection:
    """The tool fetches user-supplied domains; it must not be usable to reach
    internal infrastructure (cloud metadata, localhost, private ranges)."""
    def test_internal_ips_blocked(self):
        from shared.utils import _is_blocked_ip
        for ip in ["169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1",
                   "172.16.0.1", "0.0.0.0", "::1", "fe80::1"]:
            assert _is_blocked_ip(ip) is True, ip

    def test_public_ip_allowed(self):
        from shared.utils import _is_blocked_ip
        assert _is_blocked_ip("8.8.8.8") is False
        assert _is_blocked_ip("1.1.1.1") is False

    def test_is_safe_url_blocks_localhost_and_metadata(self):
        from shared.utils import is_safe_url
        for u in ["http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/",
                  "http://localhost:8010/trigger"]:
            safe, _ = is_safe_url(u)
            assert safe is False, u

    def test_fetch_refuses_internal(self):
        from shared.utils import http_get_with_retry
        r = http_get_with_retry("http://127.0.0.1:8010/trigger", max_attempts=1)
        assert r["status_code"] is None
        assert "SSRF" in (r["error"] or "")
