"""
Costanti condivise — severity map, provider noti, regole di classificazione.
"""

SEVERITY_MAP = {
    "new_certificate": "CRITICAL", "http_activated": "CRITICAL",
    "new_certificate_batch": "CRITICAL",
    "credential_form_detected": "CRITICAL", "brand_impersonation": "CRITICAL",
    "live_tls_cert_detected": "CRITICAL",
    "dnstwist_new_registered": "CRITICAL", "dnstwist_new_with_mx": "CRITICAL",
    "a_record_changed": "HIGH", "a_record_not_parking": "HIGH",
    "mx_record_changed": "HIGH", "new_subdomain_resolved": "HIGH",
    "http_content_changed": "HIGH", "redirect_to_new_target": "HIGH",
    "san_subdomain_discovered": "HIGH", "runtime_error": "HIGH",
    "dnstwist_new_lookalike": "HIGH",
    "variant_http_activated": "CRITICAL", "variant_new_certificate": "CRITICAL",
    "variant_dns_changed": "HIGH", "variant_http_content_changed": "HIGH",
    "variant_tls_activated": "HIGH",
    "legit_http_activated": "HIGH", "legit_http_content_changed": "CRITICAL",
    "legit_http_status_degraded": "CRITICAL", "legit_tls_activated": "HIGH",
    "dmarc_added": "MEDIUM", "dmarc_changed": "MEDIUM",
    "spf_changed": "MEDIUM", "dkim_added": "MEDIUM",
    "ns_changed": "MEDIUM", "caa_added": "MEDIUM", "caa_changed": "MEDIUM",
    "bimi_added": "MEDIUM",
    "txt_changed": "LOW", "soa_changed": "LOW", "http_headers_changed": "LOW",
    "whois_registrar_changed": "HIGH", "whois_nameservers_changed": "HIGH",
    "whois_status_changed": "MEDIUM", "whois_expiry_approaching": "MEDIUM",
    "whois_renewed": "LOW", "whois_privacy_removed": "LOW",
    "vt_malicious_detected": "CRITICAL", "vt_suspicious_detected": "HIGH",
    "vt_newly_categorized": "MEDIUM", "vt_reputation_decreased": "MEDIUM",
    "otx_pulse_detected": "HIGH", "otx_malware_associated": "CRITICAL",
    "st_new_subdomains": "HIGH", "reputation_degraded": "MEDIUM",
    "hidden_form_detected": "CRITICAL", "invisible_iframe_detected": "CRITICAL",
    "obfuscated_js_detected": "HIGH", "hidden_elements_high_risk": "CRITICAL",
    "meta_redirect_detected": "HIGH", "tracking_pixel_detected": "MEDIUM",
    "legit_hidden_form_detected": "CRITICAL",
    "legit_invisible_iframe_detected": "CRITICAL",
    "legit_obfuscated_js_detected": "CRITICAL",
    "legit_hidden_elements_detected": "CRITICAL",
    "legit_meta_redirect_detected": "CRITICAL",
    "legit_content_injected": "CRITICAL",
}

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "dkim", "mail", "smtp", "s1", "s2",
    "protonmail", "protonmail2", "protonmail3",
    "mxvault", "mandrill", "everlytickey1", "cm",
]

DEFAULT_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "pop",
    "autodiscover", "autoconfig", "login", "signin", "secure",
    "account", "auth", "sso", "portal", "admin", "cpanel", "panel",
    "api", "app", "cdn", "vpn", "remote", "owa", "control",
]

DEFAULT_SUSPICIOUS_PATTERNS = [
    r"<form[^>]*action",
    r"<input[^>]*type=[\\\"']?password",
    r"<input[^>]*type=[\\\"']?email",
    r"login|sign.?in|log.?in|accedi|entra",
    r"username|user.?name|utente",
    r"password|passwd|pwd",
    r"microsoft|office\s*365|outlook",
]

# ═══════════════════════════════════════════════════════════════
# AUTO-CLASSIFICATION: provider e IP noti
# ═══════════════════════════════════════════════════════════════

KNOWN_PARKING_NS = [
    "domaincontrol.com", "eftydns.com", "afternic.com",
    "namefind.com", "bodis.com", "sedoparking.com",
]

KNOWN_PARKING_IPS = [
    "15.197.148.33", "13.248.213.45", "13.248.169.48",
    "76.223.54.146", "3.33.130.190",
]

MARKETPLACE_NS = [
    "brandbucket.com", "namebrightdns.com", "dns-parking.com",
    "buydomains.com", "hugedomains.com",
]

# Domains registered longer ago than this predate a typical hostile-registration
# campaign. Weak threat signals on such domains are downgraded rather than alarmed on
# (see classifier: age modulation), and inert ones are classified as third parties.
AGE_THIRD_PARTY_DAYS = 540  # ~18 months

PRIVACY_MX_PROVIDERS = [
    "protonmail.ch", "tutanota.de", "pm.me", "tutamail.com",
]

FORWARDING_MX_PROVIDERS = [
    "registrar-servers.com", "forwardemail.net",
]

BUSINESS_MX_PROVIDERS = [
    "mail.protection.outlook.com", "aspmx.l.google.com",
    "google.com", "googlemail.com",
]

ENTERPRISE_CERT_PROVIDERS = [
    "tls.automattic.com", "sni.cloudflaressl.com",
]

PARKING_MX = [
    "park-mx.above.com", "parkmail.dynadot.com",
    "mailstore1.secureserver.net",
]
