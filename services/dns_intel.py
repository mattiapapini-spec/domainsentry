"""
DNS Intelligence Service (:8001)
Modulo 1 estratto dal monolite — DNS completo + DMARC/DKIM/BIMI/CAA + sottodomini.
"""

import os, logging
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import dig_query, is_valid, now_iso
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

app = FastAPI(title="DNS Intel", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("dns-intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DNS] %(message)s")

DNS_TIMEOUT = int(os.environ.get("DNS_TIMEOUT", "10"))


@app.get("/health")
def health():
    return {"status": "healthy", "service": "dns-intel", "version": "4.0.0"}


@router.get("/dns", tags=["DNS Intelligence"])
def dns_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    full: bool = Query(False, description="Include DMARC/DKIM/BIMI/CAA"),
    subdomains: bool = Query(False, description="Enumerate subdomains"),
    dkim_selectors: str = Query("", description="Comma-separated selectors override")
):
    logger.info(f"Check: {sanitize_log_input(domain)} full={full} sub={subdomains}")
    result = {
        "domain": domain, "timestamp": now_iso(),
        "records": {}, "email_auth": {}, "subdomains": {},
        "error": None
    }

    # Record base
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        rec = dig_query(domain, rtype, DNS_TIMEOUT)
        result["records"][rtype] = rec if is_valid(rec) else []

    if not full:
        return JSONResponse(content=result)

    # SPF (estratto da TXT)
    spf_records = [t for t in result["records"].get("TXT", []) if "v=spf1" in t]
    result["email_auth"]["spf"] = {
        "present": bool(spf_records),
        "records": spf_records,
        "policy": _extract_spf_policy(spf_records[0]) if spf_records else None
    }

    # DMARC
    dmarc = dig_query(f"_dmarc.{domain}", "TXT", DNS_TIMEOUT)
    dmarc_valid = dmarc if is_valid(dmarc) else []
    result["email_auth"]["dmarc"] = {
        "present": bool(dmarc_valid),
        "records": dmarc_valid
    }

    # DKIM
    selectors = dkim_selectors.split(",") if dkim_selectors else DEFAULT_DKIM_SELECTORS
    dkim_found = {}
    for sel in selectors:
        sel = sel.strip()
        if not sel:
            continue
        dk = dig_query(f"{sel}._domainkey.{domain}", "TXT", DNS_TIMEOUT)
        if is_valid(dk):
            dkim_found[sel] = dk
    result["email_auth"]["dkim"] = {
        "selectors_found": list(dkim_found.keys()),
        "selectors_tested": len(selectors),
        "records": dkim_found
    }

    # BIMI
    bimi = dig_query(f"default._bimi.{domain}", "TXT", DNS_TIMEOUT)
    result["email_auth"]["bimi"] = {
        "present": is_valid(bimi),
        "records": bimi if is_valid(bimi) else []
    }

    # CAA
    caa = dig_query(domain, "CAA", DNS_TIMEOUT)
    result["email_auth"]["caa"] = {
        "present": is_valid(caa),
        "records": caa if is_valid(caa) else []
    }

    # Sottodomini
    if subdomains:
        active = []
        for sub in DEFAULT_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            a = dig_query(fqdn, "A", DNS_TIMEOUT)
            c = dig_query(fqdn, "CNAME", DNS_TIMEOUT)
            sub_result = {
                "fqdn": fqdn,
                "A": a if is_valid(a) else [],
                "CNAME": c if is_valid(c) else []
            }
            if sub_result["A"] or sub_result["CNAME"]:
                active.append(sub_result)
        result["subdomains"] = {
            "tested": len(DEFAULT_SUBDOMAINS),
            "active": active
        }

    return JSONResponse(content=result)


def _extract_spf_policy(spf: str) -> str:
    if "-all" in spf: return "fail"
    if "~all" in spf: return "softfail"
    if "?all" in spf: return "neutral"
    if "+all" in spf: return "pass"
    return "unknown"

app.include_router(router)
