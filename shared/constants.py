"""
Costanti condivise — severity map, provider noti, regole di classificazione.
"""

# ═══════════════════════════════════════════════════════════════
# SCALA DI SEVERITÀ DEGLI ALERT
# ═══════════════════════════════════════════════════════════════
# CRITICAL è riservato all'ATTIVITÀ DOLOSA OSSERVATA: raccolta di credenziali,
# contenuto malevolo iniettato, conferma da fonti di reputazione. NON basta un
# cambio di stato — registrazione, emissione di un certificato, attivazione di un
# sito o presenza di MX — per quanto sospetto sia il contesto.
#
# Il criterio nasce da una misura: su un tenant reale i 25 alert CRITICAL emessi
# (28,4% del volume) erano TUTTI emissioni di certificati DV su domini di terzi,
# con precisione 0,00. La certificazione DV è gratuita, automatizzata e rinnovata
# ogni 60-90 giorni su gran parte del web: non è un evento critico. Un canale
# CRITICAL con precisione nulla è peggio dell'assenza del canale, perché
# desensibilizza l'analista al segnale autentico.
#
# INFO copre gli eventi di manutenzione, che non sono ni minacce ni rumore da
# nascondere: vanno registrati e tenuti fuori dalle code di triage.
SEVERITY_MAP = {
    # ── CRITICAL — attività dolosa osservata ──
    "credential_form_detected": "CRITICAL", "brand_impersonation": "CRITICAL",
    "hidden_form_detected": "CRITICAL", "invisible_iframe_detected": "CRITICAL",
    # ── Cambi di stato: rilevanti, non critici ──
    "new_certificate": "MEDIUM", "http_activated": "HIGH",
    "new_certificate_batch": "HIGH",
    "live_tls_cert_detected": "MEDIUM",
    # Una registrazione, anche con capacità mail, resta una capacità: diventa
    # CRITICAL solo quando quella capacità viene usata (decisione 2026-07-25).
    "dnstwist_new_registered": "MEDIUM", "dnstwist_new_with_mx": "HIGH",
    "a_record_changed": "HIGH", "a_record_not_parking": "HIGH",
    "mx_record_changed": "HIGH", "new_subdomain_resolved": "HIGH",
    "http_content_changed": "HIGH", "redirect_to_new_target": "HIGH",
    "san_subdomain_discovered": "HIGH", "runtime_error": "HIGH",
    "dnstwist_new_lookalike": "HIGH",
    "variant_http_activated": "HIGH", "variant_new_certificate": "MEDIUM",
    "variant_dns_changed": "HIGH", "variant_http_content_changed": "HIGH",
    "variant_tls_activated": "HIGH",
    # Sul dominio LEGITTIMO del cliente la soglia resta più bassa che sulle
    # varianti — è il suo asset — ma un contenuto che cambia non è ancora
    # un'iniezione osservata: quella è coperta dai `legit_*` qui sotto.
    "legit_http_activated": "HIGH", "legit_http_content_changed": "HIGH",
    "legit_http_status_degraded": "HIGH", "legit_tls_activated": "HIGH",
    "dmarc_added": "MEDIUM", "dmarc_changed": "MEDIUM",
    "spf_changed": "MEDIUM", "dkim_added": "MEDIUM",
    "ns_changed": "MEDIUM", "caa_added": "MEDIUM", "caa_changed": "MEDIUM",
    "bimi_added": "MEDIUM",
    "txt_changed": "LOW",
    # COL-12: dato DNS riportato dal ciclo precedente e non riosservato da 72 h. Non è
    # un'osservazione (nessun cambio visto, solo un'assenza di risposta): per questo non HIGH.
    # A/MX/NS hanno già un segnale in eventi e casi, gli altri tipi solo questo.
    "dns_stale_core": "MEDIUM", "dns_stale_other": "LOW",
    # ── INFO — manutenzione ordinaria, da registrare ma non da triagare ──
    "soa_changed": "INFO", "http_headers_changed": "INFO", "whois_renewed": "INFO",
    "whois_registrar_changed": "HIGH", "whois_nameservers_changed": "HIGH",
    "whois_status_changed": "MEDIUM", "whois_expiry_approaching": "MEDIUM",
    "whois_privacy_removed": "LOW",
    "vt_malicious_detected": "CRITICAL", "vt_suspicious_detected": "HIGH",
    "vt_newly_categorized": "MEDIUM", "vt_reputation_decreased": "MEDIUM",
    "otx_pulse_detected": "HIGH", "otx_malware_associated": "CRITICAL",
    "st_new_subdomains": "HIGH", "reputation_degraded": "MEDIUM",
    # hidden_form_detected e invisible_iframe_detected sono dichiarati in testa,
    # nel blocco CRITICAL: sono i due segnali di attività dolosa osservata.
    # Il bucket generico resta HIGH.
    "obfuscated_js_detected": "HIGH", "hidden_elements_high_risk": "HIGH",
    "meta_redirect_detected": "HIGH", "tracking_pixel_detected": "MEDIUM",
    "legit_hidden_form_detected": "CRITICAL",
    "legit_invisible_iframe_detected": "CRITICAL",
    "legit_obfuscated_js_detected": "CRITICAL",
    "legit_hidden_elements_detected": "CRITICAL",
    "legit_meta_redirect_detected": "CRITICAL",
    "legit_content_injected": "CRITICAL",
    # CLS-01z: markup morto (mai renderizzato, opaco: fallback content di un
    # iframe chiuso) verso host esterno sul dominio LEGITTIMO del cliente —
    # simmetrico ai fratelli legit_* sopra.
    "legit_suspicious_dead_markup_detected": "CRITICAL",
}

# Ordinamento della scala. Unica definizione: prima era ridichiarata in quattro
# punti (classifier, case_manager, dashboard e di nuovo nel diff), con il rischio
# che divergessero.
SEVERITY_ORDER = {"CLEAN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def severity_rank(severity: str) -> int:
    """Rango di una severità, 0 per valori sconosciuti o assenti."""
    return SEVERITY_ORDER.get((severity or "").upper(), 0)


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

# ═══════════════════════════════════════════════════════════════
# REPUTAZIONE
# ═══════════════════════════════════════════════════════════════

# COL-16: il testo con cui il collector di reputazione scrive in `error` l'esito 404 di
# VirusTotal (dominio sconosciuto a VT). Collector e lettori (`reputation_source_unobserved`)
# distinguono quell'esito dai guasti veri da questa stringa: un letterale ripetuto in più file
# diverge in silenzio al primo ritocco di uno solo.
VT_NOT_FOUND_ERROR = "not found on VT"
