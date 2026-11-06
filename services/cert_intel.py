"""
Certificate Intelligence Service (:8002)
Modulo 2+6 estratto — Certificate Transparency via crt.sh + TLS live inspection.
"""

import os, logging, json, time, threading
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

# COL-04: cache locale con TTL sull'esito della query crt.sh, per non ripetere una
# query di rete per lo stesso dominio a distanza di pochi millisecondi/minuti nella
# stessa esecuzione di pipeline. TTL breve (default 5 min, non le 24h di WHOIS): i
# dati CT cambiano più spesso di un WHOIS e la cache serve a evitare ripetizioni
# ravvicinate, non a sostituire query legittimamente distanziate nel tempo.
# Dimensione limitata con sfratto FIFO (come whois_intel.py) per non crescere senza
# limite; a differenza di whois_intel.py l'accesso è protetto da lock esplicito, per
# non introdurre la stessa corsa già registrata come CODE-06.
CT_CACHE_TTL = int(os.environ.get("CT_CACHE_TTL", "300"))
CT_CACHE_MAX_SIZE = int(os.environ.get("CT_CACHE_MAX_SIZE", "500"))
_ct_cache = {}
_ct_cache_order = []
_ct_cache_lock = threading.Lock()


def _ct_cache_get(key):
    """Ritorna l'esito cache se presente e ancora entro il TTL, altrimenti None."""
    with _ct_cache_lock:
        cached = _ct_cache.get(key)
        if cached and (time.time() - cached["cached_at"]) < CT_CACHE_TTL:
            return cached
    return None


def _ct_cache_set(key, ct_certificates, san_subdomains_discovered, error):
    """Salva l'esito della query crt.sh per `key`, con sfratto FIFO oltre CT_CACHE_MAX_SIZE."""
    with _ct_cache_lock:
        if key in _ct_cache:
            _ct_cache_order.remove(key)
        elif len(_ct_cache) >= CT_CACHE_MAX_SIZE:
            oldest = _ct_cache_order.pop(0)
            _ct_cache.pop(oldest, None)
        _ct_cache[key] = {
            "ct_certificates": ct_certificates,
            "san_subdomains_discovered": san_subdomains_discovered,
            "error": error,
            "cached_at": time.time(),
        }
        _ct_cache_order.append(key)


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

    # crt.sh query — servita da cache locale se già interrogata di recente per lo
    # stesso dominio (COL-04): crt.sh risponde 502 sulla maggioranza dei domini nei
    # tenant campionati, ogni query risparmiata conta.
    cache_key = (domain, include_subdomains)
    cached = _ct_cache_get(cache_key)
    if cached is not None:
        result["ct_certificates"] = cached["ct_certificates"]
        result["san_subdomains_discovered"] = cached["san_subdomains_discovered"]
        result["error"] = cached["error"]
    else:
        try:
            url = f"https://crt.sh/?q={query}&output=json"
            # SEC-16: crt.sh è un host fisso e fidato con JSON legittimamente
            # più grande del cap generico — cap proprio (MAX_CRTSH_BYTES, 10MB)
            # invece del default di http_get_with_retry (2MB).
            resp = http_get_with_retry(url, timeout=CRTSH_TIMEOUT, verify_ssl=True, max_attempts=2,
                                       max_bytes=MAX_CRTSH_BYTES)
            if resp["status_code"] == 200 and resp["content"]:
                # SEC-16: nessun troncamento qui — `http_get_with_retry` (sopra)
                # riceve già `max_bytes=MAX_CRTSH_BYTES` e garantisce
                # len(content) <= MAX_CRTSH_BYTES via streaming con stop al cap;
                # un secondo controllo post-download sulla stessa soglia era dead
                # code irraggiungibile.
                content = resp["content"]
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

        # G6 su COL-04: un esito di errore non è mai stato un esito valido da
        # memorizzare — cachiamo solo il successo. crt.sh risponde 502 sul
        # 76-95% dei domini nei tenant campionati: cachare l'errore con lo
        # stesso TTL di un esito valido trasformava un fallimento transitorio
        # in un buco di enrichment di 5 minuti anche a servizio recuperato.
        if result["error"] is None:
            _ct_cache_set(cache_key, result["ct_certificates"], result["san_subdomains_discovered"], result["error"])

    # TLS live inspection
    if tls_live:
        result["tls_live"] = inspect_tls(domain)

    return JSONResponse(content=result)

app.include_router(router)
