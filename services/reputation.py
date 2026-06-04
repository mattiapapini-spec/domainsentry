"""
Reputation Service (:8005)
Modulo 9 estratto — VirusTotal, AlienVault OTX, SecurityTrails + risk scoring.
"""

import os, logging, time
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = FastAPI(title="Reputation", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("reputation")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [REP] %(message)s")

VT_API_KEY = os.environ.get("VT_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
ST_API_KEY = os.environ.get("ST_API_KEY", "")


@app.get("/health")
def health():
    return {"status": "healthy", "service": "reputation", "version": "4.0.0",
            "sources": {"vt": bool(VT_API_KEY), "otx": bool(OTX_API_KEY), "st": bool(ST_API_KEY)}}


@router.get("/reputation", tags=["Reputation"])
def reputation_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    sources: str = Query("vt,otx,st", description="Comma-separated sources")
):
    logger.info(f"Check: {sanitize_log_input(domain)} sources={sources}")
    requested = set(s.strip() for s in sources.split(","))

    result = {
        "domain": domain, "timestamp": now_iso(),
        "virustotal": None, "otx": None, "securitytrails": None,
        "risk_score": 0, "risk_level": "unknown", "error": None
    }

    if "vt" in requested and VT_API_KEY:
        result["virustotal"] = _check_vt(domain)
    if "otx" in requested and OTX_API_KEY:
        result["otx"] = _check_otx(domain)
    if "st" in requested and ST_API_KEY:
        result["securitytrails"] = _check_st(domain)

    result["risk_score"] = _calc_score(result)
    result["risk_level"] = _score_to_level(result["risk_score"])

    return JSONResponse(content=result)


def _check_vt(domain: str) -> dict:
    r = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
         "reputation": 0, "categories": {}, "error": None}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                            headers={"x-apikey": VT_API_KEY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            r["malicious"] = stats.get("malicious", 0)
            r["suspicious"] = stats.get("suspicious", 0)
            r["undetected"] = stats.get("undetected", 0)
            r["harmless"] = stats.get("harmless", 0)
            r["reputation"] = data.get("reputation", 0)
            r["categories"] = data.get("categories", {})
        elif resp.status_code == 404:
            r["error"] = "not found on VT"
        else:
            r["error"] = f"HTTP {resp.status_code}"
        time.sleep(16)  # VT free: 4 req/min
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


def _check_otx(domain: str) -> dict:
    r = {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [], "error": None}
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                            headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            r["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            r["pulse_titles"] = [p.get("name", "") for p in pulses[:5]]
            r["tags"] = list(set(t for p in pulses for t in p.get("tags", [])))[:20]
            r["malware_families"] = list(set(
                m.get("display_name", "") for p in pulses
                for m in p.get("malware_families", [])
            ))
        else:
            r["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


def _check_st(domain: str) -> dict:
    r = {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None, "error": None}
    try:
        resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}",
                            headers={"APIKEY": ST_API_KEY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            r["subdomain_count"] = data.get("subdomain_count", 0)
            r["current_dns"] = data.get("current_dns", {})
            r["alexa_rank"] = data.get("alexa_rank")
        else:
            r["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        r["error"] = sanitize_error(e)
    return r


def _calc_score(results: dict) -> int:
    score = 0
    vt = results.get("virustotal")
    if vt and not vt.get("error"):
        score += min(vt.get("malicious", 0) * 10, 50)
        score += min(vt.get("suspicious", 0) * 5, 20)
        if vt.get("reputation", 0) < -5:
            score += 10
    otx = results.get("otx")
    if otx and not otx.get("error"):
        score += min(otx.get("pulse_count", 0) * 5, 30)
        if otx.get("malware_families"):
            score += 20
    return min(score, 100)


def _score_to_level(score: int) -> str:
    if score == 0: return "clean"
    if score <= 20: return "low"
    if score <= 50: return "medium"
    if score <= 80: return "high"
    return "critical"

app.include_router(router)
