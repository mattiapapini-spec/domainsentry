"""
Shared utilities — funzioni comuni a tutti i microservizi.
Estratte dal monolite v3.1.
"""

import subprocess
import hashlib
import ssl
import re
import time
import logging
import socket
from datetime import datetime, timezone, timedelta

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

logger = logging.getLogger("shared")


# ═══════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════

def dig_query(fqdn: str, rtype: str, timeout: int = 10) -> list[str]:
    try:
        proc = subprocess.run(
            ["dig", "+short", "+ndots=1", f"+time={timeout}", "+tries=2",
             "+noidnout", fqdn, rtype],
            capture_output=True, text=True, timeout=timeout + 10)
        lines = [l.strip().rstrip(".") for l in proc.stdout.strip().split("\n") if l.strip()]
        return sorted(lines)
    except FileNotFoundError:
        return ["ERROR: dig not found"]
    except subprocess.TimeoutExpired:
        return ["ERROR: timeout"]
    except Exception as e:
        return [f"ERROR: {e}"]


def is_valid(records: list[str]) -> bool:
    return bool(records) and records[0] != "" and not records[0].startswith("ERROR")


# ═══════════════════════════════════════════════════════════════
# HTTP
# ═══════════════════════════════════════════════════════════════

def http_get_with_retry(url, timeout=15, verify_ssl=False, max_attempts=3, base_delay=2):
    result = {"status_code": None, "content": None, "headers": {},
              "final_url": None, "error": None, "attempts": 0}
    ua = "Mozilla/5.0 (compatible; SOC-DomainIntelligence/4.0)"
    retryable = {429, 500, 502, 503, 504}

    for attempt in range(1, max_attempts + 1):
        result["attempts"] = attempt
        result["error"] = None
        try:
            if HAS_REQUESTS:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = req_lib.get(url, timeout=timeout, allow_redirects=True,
                                   headers={"User-Agent": ua}, verify=verify_ssl)
                result.update({"status_code": resp.status_code, "content": resp.content,
                               "headers": dict(resp.headers),
                               "final_url": resp.url if resp.url != url else None})
                if resp.status_code in retryable and attempt < max_attempts:
                    time.sleep(base_delay * (2 ** (attempt - 1)))
                    continue
                return result
            else:
                req = urllib.request.Request(url, headers={"User-Agent": ua})
                ctx = ssl.create_default_context()
                if not verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    result.update({"content": resp.read(), "status_code": resp.getcode(),
                                   "headers": dict(resp.headers),
                                   "final_url": resp.geturl() if resp.geturl() != url else None})
                return result
        except Exception as e:
            result["error"] = f"Attempt {attempt}/{max_attempts}: {e}"
            if attempt < max_attempts:
                time.sleep(base_delay * (2 ** (attempt - 1)))
    return result


# ═══════════════════════════════════════════════════════════════
# TLS
# ═══════════════════════════════════════════════════════════════

def inspect_tls(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    result = {"connected": False, "certificate": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    result["connected"] = True
                    result["certificate"] = {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                    }
                else:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        result["connected"] = True
                        result["certificate"] = {
                            "der_sha256": hashlib.sha256(der).hexdigest(),
                            "note": "binary cert only"
                        }
    except Exception as e:
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════════
# HTML Processing
# ═══════════════════════════════════════════════════════════════

def normalize_html_for_fingerprint(html: str) -> str:
    """Normalizza HTML rimuovendo rumore dinamico per fingerprinting stabile."""
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    text = re.sub(r'\b\d{10,13}\b', '', text)  # timestamps
    text = re.sub(r'[0-9a-f]{32,64}', '', text, flags=re.IGNORECASE)  # hashes/tokens
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_visible_text(html: str) -> str:
    """Estrae testo visibile da HTML."""
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def detect_suspicious_patterns(html: str, patterns: list[str]) -> list[dict]:
    """Cerca pattern sospetti in HTML."""
    findings = []
    for pattern in patterns:
        try:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern": pattern,
                    "count": len(matches),
                    "samples": matches[:3]
                })
        except re.error:
            pass
    return findings


def detect_hidden_elements(html: str, self_domain: str = None) -> dict:
    """
    Rileva tag nascosti e contenuto offuscato in HTML.
    Identifica infrastruttura offensiva preparata ma non visibile:
    hidden forms, invisible iframes, tracking pixels, meta redirect,
    JS offuscato, commenti con codice staged, data exfiltration.

    self_domain: se fornito, le risorse ospitate sullo stesso dominio (o suoi
    sottodomini) NON vengono contate come "esterne" — un sito che carica i propri
    /wp-content/... non è un indicatore di rischio.
    """
    findings = {
        "hidden_inputs": [],
        "hidden_forms": [],
        "invisible_iframes": [],
        "tracking_pixels": [],
        "meta_redirects": [],
        "obfuscated_js": [],
        "hidden_divs_with_content": [],
        "external_resources": [],
        "large_comments": [],
        "base64_content": [],
        "risk_indicators": 0,
        "summary": []
    }
    # Normalizza il dominio del sito stesso (per escludere risorse self-hosted)
    _self = (self_domain or "").lower().lstrip("www.")

    # ── 1. Hidden input fields ──
    hidden_inputs = re.findall(
        r'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*>', html, re.IGNORECASE)
    for inp in hidden_inputs:
        name = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', inp, re.IGNORECASE)
        value = re.search(r'value\s*=\s*["\']?([^"\'>\s]*)', inp, re.IGNORECASE)
        findings["hidden_inputs"].append({
            "tag": inp[:200],
            "name": name.group(1) if name else None,
            "value": (value.group(1)[:100] if value else None)
        })

    # ── 2. Hidden forms (display:none, visibility:hidden, opacity:0) ──
    hidden_form_patterns = [
        r'<form[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?</form>',
        r'<form[^>]*style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>.*?</form>',
        r'<form[^>]*style\s*=\s*["\'][^"\']*opacity\s*:\s*0[^"\']*["\'][^>]*>.*?</form>',
        r'<form[^>]*class\s*=\s*["\'][^"\']*hidden[^"\']*["\'][^>]*>.*?</form>',
    ]
    for pat in hidden_form_patterns:
        for m in re.finditer(pat, html, re.IGNORECASE | re.DOTALL):
            action = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', m.group(), re.IGNORECASE)
            findings["hidden_forms"].append({
                "snippet": m.group()[:300],
                "action": action.group(1) if action else None,
                "technique": "css_hidden"
            })

    # ── 3. Invisible iframes ──
    iframes = re.finditer(r'<iframe[^>]*>(.*?)</iframe>', html, re.IGNORECASE | re.DOTALL)
    for iframe in iframes:
        tag = iframe.group()
        is_hidden = False
        technique = []

        # Dimensioni 0/1px
        if re.search(r'(width|height)\s*=\s*["\']?\s*[01]\s*(px)?["\']?', tag, re.IGNORECASE):
            is_hidden = True
            technique.append("zero_dimension")
        # display:none / visibility:hidden / opacity:0
        if re.search(r'style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)', tag, re.IGNORECASE):
            is_hidden = True
            technique.append("css_hidden")
        # Position absolute con negative offset
        if re.search(r'style\s*=\s*["\'][^"\']*(left|top)\s*:\s*-\d{3,}', tag, re.IGNORECASE):
            is_hidden = True
            technique.append("offscreen")

        if is_hidden:
            src = re.search(r'src\s*=\s*["\']?([^"\'>\s]+)', tag, re.IGNORECASE)
            findings["invisible_iframes"].append({
                "tag": tag[:300],
                "src": src.group(1) if src else None,
                "technique": technique
            })

    # ── 4. Tracking pixels (1x1 img) ──
    imgs = re.finditer(r'<img[^>]*>', html, re.IGNORECASE)
    for img in imgs:
        tag = img.group()
        w = re.search(r'width\s*=\s*["\']?\s*1\s*(px)?["\']?', tag, re.IGNORECASE)
        h = re.search(r'height\s*=\s*["\']?\s*1\s*(px)?["\']?', tag, re.IGNORECASE)
        if w and h:
            src = re.search(r'src\s*=\s*["\']?([^"\'>\s]+)', tag, re.IGNORECASE)
            findings["tracking_pixels"].append({
                "tag": tag[:200],
                "src": src.group(1) if src else None
            })

    # ── 5. Meta refresh redirects ──
    meta_refresh = re.finditer(
        r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?([^"\'> ]+)',
        html, re.IGNORECASE)
    for m in meta_refresh:
        content = m.group(1)
        url = re.search(r'url\s*=\s*(.*)', content, re.IGNORECASE)
        findings["meta_redirects"].append({
            "content": content[:200],
            "target_url": url.group(1).strip() if url else None,
            "delay": content.split(";")[0].strip() if ";" in content else content.strip()
        })

    # ── 6. Obfuscated JavaScript ──
    scripts = re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
    for script in scripts:
        js = script.group(1).strip()
        if not js:
            continue
        obfuscation_indicators = []

        if 'eval(' in js:
            obfuscation_indicators.append("eval")
        if 'atob(' in js:
            obfuscation_indicators.append("atob_base64")
        if 'document.write(' in js:
            obfuscation_indicators.append("document_write")
        if 'unescape(' in js or 'decodeURI(' in js:
            obfuscation_indicators.append("unescape")
        if 'String.fromCharCode' in js:
            obfuscation_indicators.append("fromCharCode")
        # Hex encoding massiccio
        hex_count = len(re.findall(r'\\x[0-9a-fA-F]{2}', js))
        if hex_count > 10:
            obfuscation_indicators.append(f"hex_encoding_{hex_count}")
        # Unicode encoding massiccio
        unicode_count = len(re.findall(r'\\u[0-9a-fA-F]{4}', js))
        if unicode_count > 10:
            obfuscation_indicators.append(f"unicode_encoding_{unicode_count}")
        # Array di numeri sospetto (char code obfuscation)
        if re.search(r'\[\s*\d+\s*(?:,\s*\d+\s*){20,}\]', js):
            obfuscation_indicators.append("charcode_array")
        # Variabili di singola lettera in massa (minified/obfuscated)
        if len(js) > 500 and len(set(re.findall(r'\b[a-z]\b', js))) > 15:
            # potrebbe essere solo minified, non obfuscated
            if 'eval' in js or 'atob' in js:
                obfuscation_indicators.append("minified_with_eval")

        if obfuscation_indicators:
            # unicode/hex encoding DA SOLI non indicano offuscamento malevolo:
            # i file WordPress (wp-emoji) e molti bundle minificati contengono
            # decine di sequenze \uXXXX legittime. Marca "offuscato" solo se c'è
            # un segnale di vera offuscazione (eval/atob/fromCharCode/document.write/
            # unescape/charcode_array/minified_with_eval), oppure encoding + uno di questi.
            strong = {"eval", "atob_base64", "document_write", "unescape",
                      "fromCharCode", "charcode_array", "minified_with_eval"}
            has_strong = any(ind in strong for ind in obfuscation_indicators)
            only_encoding = all(ind.startswith("hex_encoding") or ind.startswith("unicode_encoding")
                                for ind in obfuscation_indicators)
            if has_strong or not only_encoding:
                findings["obfuscated_js"].append({
                    "snippet": js[:300],
                    "length": len(js),
                    "indicators": obfuscation_indicators
                })

    # ── 7. Hidden divs with content ──
    hidden_div_patterns = [
        r'<div[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]*style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]*class\s*=\s*["\'][^"\']*hidden[^"\']*["\'][^>]*>(.*?)</div>',
    ]
    for pat in hidden_div_patterns:
        for m in re.finditer(pat, html, re.IGNORECASE | re.DOTALL):
            inner = m.group(1).strip()
            # Solo se il div nascosto contiene contenuto significativo
            visible_text = re.sub(r'<[^>]+>', '', inner).strip()
            if len(visible_text) > 20:
                findings["hidden_divs_with_content"].append({
                    "snippet": m.group()[:400],
                    "visible_text_preview": visible_text[:200],
                    "text_length": len(visible_text),
                    "contains_form": bool(re.search(r'<form', inner, re.IGNORECASE)),
                    "contains_input": bool(re.search(r'<input', inner, re.IGNORECASE)),
                    "contains_link": bool(re.search(r'<a\s', inner, re.IGNORECASE)),
                })

    # ── 8. External resources da domini terzi ──
    def _host_of(u):
        m = re.match(r'https?://([^/]+)', u, re.IGNORECASE)
        return (m.group(1).lower().lstrip("www.") if m else "")
    ext_resources = set()
    for attr in ['src', 'href', 'action', 'data']:
        for m in re.finditer(rf'{attr}\s*=\s*["\']?(https?://[^"\'>\s]+)', html, re.IGNORECASE):
            url = m.group(1)
            host = _host_of(url)
            # Escludi risorse self-hosted: stesso dominio o suo sottodominio.
            # Un sito che carica i propri /wp-content/, /assets/... non è "esterno".
            if _self and (host == _self or host.endswith("." + _self)):
                continue
            ul = url.lower()
            # Escludi CDN noti e risorse standard (inclusi CDN WordPress/font comuni)
            if not any(safe in ul for safe in [
                'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jquery.com',
                'bootstrapcdn.com', 'cdnjs.com', 'jsdelivr.net', 'unpkg.com',
                'google-analytics.com', 'googletagmanager.com', 'facebook.com',
                'twitter.com', 'schema.org', 'w3.org',
                'wp.com', 'wordpress.org', 'gravatar.com', 'fonts.', 'fontawesome',
                'youtube.com', 'vimeo.com', 'linkedin.com', 'instagram.com'
            ]):
                ext_resources.add(url)
    findings["external_resources"] = list(ext_resources)[:20]

    # ── 9. Large HTML comments (staged code) ──
    comments = re.finditer(r'<!--(.*?)-->', html, re.DOTALL)
    for c in comments:
        content = c.group(1).strip()
        if len(content) > 200:
            has_tags = bool(re.search(r'<\w+', content))
            has_js = bool(re.search(r'function\s|var\s|document\.|window\.', content))
            findings["large_comments"].append({
                "length": len(content),
                "preview": content[:200],
                "contains_html_tags": has_tags,
                "contains_javascript": has_js
            })

    # ── 10. Base64 encoded content inline ──
    # Cerca stringhe base64 lunghe (non in contesti normali come data:image per favicon)
    b64_matches = re.finditer(r'(?:atob\s*\(\s*["\']|data:[^;]+;base64,)([A-Za-z0-9+/=]{100,})', html)
    for m in b64_matches:
        b64 = m.group(1)
        findings["base64_content"].append({
            "length": len(b64),
            "preview": b64[:80] + "...",
            "context": html[max(0, m.start()-30):m.start()][-50:]
        })

    # ── Risk scoring ──
    risk = 0
    if findings["hidden_forms"]:
        risk += 30
        findings["summary"].append(f"{len(findings['hidden_forms'])} form nascosti — possibile credential harvesting")
    if findings["invisible_iframes"]:
        risk += 25
        findings["summary"].append(f"{len(findings['invisible_iframes'])} iframe invisibili — possibile contenuto malevolo embedato")
    if findings["obfuscated_js"]:
        risk += 20
        findings["summary"].append(f"{len(findings['obfuscated_js'])} script offuscati — indicatori: {', '.join(findings['obfuscated_js'][0].get('indicators', []))}")
    if findings["meta_redirects"]:
        risk += 20
        findings["summary"].append(f"Meta refresh verso: {findings['meta_redirects'][0].get('target_url', '?')}")
    if findings["hidden_inputs"] and len(findings["hidden_inputs"]) > 3:
        risk += 15
        findings["summary"].append(f"{len(findings['hidden_inputs'])} input nascosti — possibile form di raccolta dati")
    if findings["tracking_pixels"]:
        risk += 10
        findings["summary"].append(f"{len(findings['tracking_pixels'])} pixel di tracking")
    if findings["hidden_divs_with_content"]:
        for div in findings["hidden_divs_with_content"]:
            if div.get("contains_form"):
                risk += 25
                findings["summary"].append("Div nascosto contenente un form — alta probabilità di phishing preparato")
                break
        else:
            risk += 10
            findings["summary"].append(f"{len(findings['hidden_divs_with_content'])} div nascosti con contenuto")
    if findings["large_comments"]:
        for comm in findings["large_comments"]:
            if comm.get("contains_html_tags") or comm.get("contains_javascript"):
                risk += 15
                findings["summary"].append("Commenti HTML con codice stageable — possibile kit in attesa di attivazione")
                break
    if findings["base64_content"]:
        risk += 15
        findings["summary"].append(f"{len(findings['base64_content'])} blocchi base64 inline")

    findings["risk_indicators"] = min(risk, 100)

    # Pulizia: rimuovi liste vuote per output leggibile
    findings = {k: v for k, v in findings.items() if v or k in ("risk_indicators", "summary")}

    return findings


# ═══════════════════════════════════════════════════════════════
# Hashing
# ═══════════════════════════════════════════════════════════════

def content_hash(content: bytes | str) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    return hashlib.sha256(content).hexdigest()


# ═══════════════════════════════════════════════════════════════
# Time helpers
# ═══════════════════════════════════════════════════════════════

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_check_due(last_checked_iso: str | None, hours: int) -> bool:
    if not last_checked_iso:
        return True
    try:
        last_dt = datetime.fromisoformat(last_checked_iso)
        return (datetime.now(timezone.utc) - last_dt) >= timedelta(hours=hours)
    except (ValueError, TypeError):
        return True
