"""
WHOIS Intelligence Service (:8004)
Modulo 8 estratto — WHOIS lookup con parsing strutturato.
"""

import os, logging, subprocess, re, time, threading
from datetime import datetime, timezone
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="WHOIS Intel", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("whois-intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [WHOIS] %(message)s")

WHOIS_TIMEOUT = int(os.environ.get("WHOIS_TIMEOUT", "10"))
WHOIS_DELAY = float(os.environ.get("WHOIS_DELAY", "2"))

# Simple LRU cache with max size
_cache = {}
_cache_order = []
CACHE_TTL = int(os.environ.get("CACHE_TTL", "86400"))
CACHE_MAX_SIZE = int(os.environ.get("CACHE_MAX_SIZE", "500"))

# Rate limiting via timestamp (non-blocking between distinct domains)
_last_query_time = 0.0
_rate_lock = threading.Lock()

try:
    import whois as whois_lib
    HAS_WHOIS_LIB = True
except ImportError:
    HAS_WHOIS_LIB = False


@app.get("/health")
def health():
    return {"status": "healthy", "service": "whois-intel", "version": "4.0.0",
            "whois_lib": HAS_WHOIS_LIB}


@router.get("/whois", tags=["WHOIS Intelligence"])
def whois_check(domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")):
    logger.info(f"Check: {sanitize_log_input(domain)}")

    # Cache check
    cached = _cache.get(domain)
    if cached and (time.time() - cached["_cached_at"]) < CACHE_TTL:
        logger.info(f"Cache hit: {sanitize_log_input(domain)}")
        return JSONResponse(content=cached["data"])

    result = {
        "domain": domain, "timestamp": now_iso(),
        "registrar": None, "creation_date": None, "expiration_date": None,
        "updated_date": None, "status": [], "nameservers": [],
        "registrant": {"name": None, "org": None, "country": None, "email": None},
        "privacy_protected": False, "dnssec": False,
        "age_days": None, "error": None
    }

    # Rate limiting: only wait the remaining time since last real query
    global _last_query_time
    with _rate_lock:
        elapsed = time.time() - _last_query_time
        if elapsed < WHOIS_DELAY:
            time.sleep(WHOIS_DELAY - elapsed)
        _last_query_time = time.time()

    try:
        if HAS_WHOIS_LIB:
            w = whois_lib.whois(domain)
            result["registrar"] = _str(w.registrar)
            result["creation_date"] = _norm_date(w.creation_date)
            result["expiration_date"] = _norm_date(w.expiration_date)
            result["updated_date"] = _norm_date(w.updated_date)
            result["status"] = _to_list(w.status)
            result["nameservers"] = [ns.lower() for ns in _to_list(w.name_servers)] if w.name_servers else []
            result["registrant"]["name"] = _str(getattr(w, "name", None))
            result["registrant"]["org"] = _str(getattr(w, "org", None))
            result["registrant"]["country"] = _str(getattr(w, "country", None))
            result["registrant"]["email"] = _str(getattr(w, "emails", None))
            result["dnssec"] = str(getattr(w, "dnssec", "")).lower() not in ("", "unsigned", "none")
        else:
            result = _whois_cli_fallback(domain, result)

        # Inferenze
        reg_name = (result["registrant"]["name"] or "").lower()
        reg_org = (result["registrant"]["org"] or "").lower()
        privacy_keywords = ["privacy", "redacted", "withheld", "whoisguard",
                            "domains by proxy", "contact privacy", "identity protection"]
        result["privacy_protected"] = any(
            kw in reg_name or kw in reg_org for kw in privacy_keywords
        ) or (not result["registrant"]["name"] and not result["registrant"]["org"])

        if result["creation_date"]:
            try:
                created = datetime.fromisoformat(result["creation_date"])
                result["age_days"] = (datetime.now(timezone.utc) - created).days
            except (ValueError, TypeError):
                pass

    except Exception as e:
        result["error"] = sanitize_error(e)
        logger.error(f"Errore WHOIS {sanitize_log_input(domain)}: {e}")

    # Cache store with LRU eviction
    if len(_cache) >= CACHE_MAX_SIZE:
        oldest = _cache_order.pop(0)
        _cache.pop(oldest, None)
    _cache[domain] = {"data": result, "_cached_at": time.time()}
    if domain in _cache_order:
        _cache_order.remove(domain)
    _cache_order.append(domain)

    return JSONResponse(content=result)


def _whois_cli_fallback(domain: str, result: dict) -> dict:
    try:
        proc = subprocess.run(["whois", domain], capture_output=True, text=True,
                              timeout=WHOIS_TIMEOUT + 5)
        raw = proc.stdout
        result["registrar"] = _extract(raw, r"Registrar:\s*(.+)")
        result["creation_date"] = _extract(raw, r"Creation Date:\s*(.+)")
        result["expiration_date"] = _extract(raw, r"Expir\w+ Date:\s*(.+)")
        result["updated_date"] = _extract(raw, r"Updated Date:\s*(.+)")
        ns_matches = re.findall(r"Name Server:\s*(\S+)", raw, re.IGNORECASE)
        result["nameservers"] = [ns.lower().rstrip(".") for ns in ns_matches]
        status_matches = re.findall(r"Domain Status:\s*(\S+)", raw, re.IGNORECASE)
        result["status"] = status_matches
    except Exception as e:
        result["error"] = f"CLI fallback: {e}"
    return result


def _str(val) -> str | None:
    if val is None: return None
    if isinstance(val, list): return str(val[0]) if val else None
    return str(val).strip() or None


def _norm_date(val) -> str | None:
    if val is None: return None
    if isinstance(val, list): val = val[0]
    if isinstance(val, datetime): return val.isoformat()
    return str(val).strip() or None


def _to_list(val) -> list:
    if val is None: return []
    if isinstance(val, list): return val
    return [val]


def _extract(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else None

app.include_router(router)
