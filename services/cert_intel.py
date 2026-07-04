"""
Certificate Intelligence Service (:8002)
Modulo 2+6 estratto — Certificate Transparency via crt.sh + TLS live inspection.
"""

import os, logging, json
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import http_get_with_retry, inspect_tls, now_iso

app = FastAPI(title="Cert Intel", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("cert-intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CERT] %(message)s")

CRTSH_TIMEOUT = int(os.environ.get("CRTSH_TIMEOUT", "30"))
MAX_CRTSH_BYTES = int(os.environ.get("MAX_CRTSH_BYTES", str(10 * 1024 * 1024)))  # 10MB


@app.get("/health")
def health():
    return {"status": "healthy", "service": "cert-intel", "version": "4.0.0"}


@router.get("/cert", tags=["Certificate Intelligence"])
def cert_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    include_subdomains: bool = Query(True, description="Wildcard *.domain"),
    tls_live: bool = Query(False, description="TLS live inspection")
):
    logger.info(f"Check: {sanitize_log_input(domain)} sub={include_subdomains} tls={tls_live}")
    query = f"%.{domain}" if include_subdomains else domain
    result = {
        "domain": domain, "timestamp": now_iso(),
        "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
        "tls_live": None,
        "san_subdomains_discovered": [],
        "error": None
    }

    # crt.sh query
    try:
        url = f"https://crt.sh/?q={query}&output=json"
        resp = http_get_with_retry(url, timeout=CRTSH_TIMEOUT, verify_ssl=True, max_attempts=2)
        if resp["status_code"] == 200 and resp["content"]:
            # Cap response size: cert-heavy domains can return many MB
            content = resp["content"]
            if len(content) > MAX_CRTSH_BYTES:
                result["error"] = f"crt.sh response too large ({len(content)} bytes), truncated analysis"
                content = None
            certs = json.loads(content) if content else []
            unique_cn = set()
            san_subs = set()
            cert_list = []

            for cert in certs:
                cn = cert.get("common_name", "")
                unique_cn.add(cn)
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name != domain and name.endswith(f".{domain}"):
                        san_subs.add(name)

                cert_list.append({
                    "id": cert.get("id"),
                    "common_name": cn,
                    "name_value": name_value,
                    "issuer_name": cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "entry_timestamp": cert.get("entry_timestamp", ""),
                })

            result["ct_certificates"] = {
                "total": len(cert_list),
                "unique_cn": sorted(unique_cn),
                "certificates": cert_list
            }
            result["san_subdomains_discovered"] = sorted(san_subs)
        else:
            result["error"] = f"crt.sh HTTP {resp['status_code']}: {resp.get('error', '')}"
    except Exception as e:
        result["error"] = sanitize_error(e)

    # TLS live inspection
    if tls_live:
        result["tls_live"] = inspect_tls(domain)

    return JSONResponse(content=result)

app.include_router(router)
