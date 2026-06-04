"""
HTTP Fingerprint Service (:8003)
Modulo 5 estratto — Content hash, form detection, brand impersonation.
"""

import os, logging, hashlib, re
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import (http_get_with_retry, normalize_html_for_fingerprint,
                           extract_visible_text, detect_suspicious_patterns,
                           detect_hidden_elements, content_hash, now_iso)
from shared.constants import DEFAULT_SUSPICIOUS_PATTERNS

app = FastAPI(title="HTTP Fingerprint", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("http-fp")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [HTTP] %(message)s")

HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "15"))


@app.get("/health")
def health():
    return {"status": "healthy", "service": "http-fingerprint", "version": "4.0.0"}


@router.get("/http", tags=["HTTP Fingerprint"])
def http_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    check_www: bool = Query(True),
    brand_keywords: str = Query("", description="Comma-separated brand keywords"),
    detect_hidden: bool = Query(True, description="Rileva tag nascosti e contenuto offuscato")
):
    logger.info(f"Check: {sanitize_log_input(domain)} www={check_www} hidden={detect_hidden}")
    targets = [domain]
    if check_www:
        targets.append(f"www.{domain}")

    patterns = DEFAULT_SUSPICIOUS_PATTERNS.copy()
    if brand_keywords:
        for kw in brand_keywords.split(","):
            kw = kw.strip()
            if kw:
                patterns.append(re.escape(kw))

    result = {
        "domain": domain, "timestamp": now_iso(),
        "checks": [],
        "overall_status": "down",
        "hidden_elements_risk": 0,
        "error": None
    }

    any_active = False
    max_hidden_risk = 0
    for target in targets:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}"
            resp = http_get_with_retry(url, timeout=HTTP_TIMEOUT)
            check = {
                "url": url,
                "status_code": resp["status_code"],
                "content_length": len(resp["content"]) if resp["content"] else 0,
                "title": None,
                "server": resp["headers"].get("Server", resp["headers"].get("server", "")),
                "content_hash": None,
                "content_hash_canonical": None,
                "visible_text_hash": None,
                "suspicious_patterns": [],
                "hidden_elements": None,
                "redirect_chain": resp["final_url"],
                "error": resp["error"]
            }

            if resp["status_code"] and resp["status_code"] < 400 and resp["content"]:
                any_active = True
                html = resp["content"].decode("utf-8", errors="replace") if isinstance(resp["content"], bytes) else resp["content"]
                check["content_hash"] = content_hash(html)
                check["content_hash_canonical"] = content_hash(normalize_html_for_fingerprint(html))
                check["visible_text_hash"] = content_hash(extract_visible_text(html))

                title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                check["title"] = title_match.group(1).strip()[:200] if title_match else None

                check["suspicious_patterns"] = detect_suspicious_patterns(html, patterns)

                # ── Hidden element detection ──
                if detect_hidden:
                    hidden = detect_hidden_elements(html)
                    check["hidden_elements"] = hidden
                    risk = hidden.get("risk_indicators", 0)
                    if risk > max_hidden_risk:
                        max_hidden_risk = risk

            result["checks"].append(check)

    if any_active:
        result["overall_status"] = "active"
    elif any(c["status_code"] and c["status_code"] >= 400 for c in result["checks"]):
        result["overall_status"] = "error"

    result["hidden_elements_risk"] = max_hidden_risk

    return JSONResponse(content=result)

app.include_router(router)
