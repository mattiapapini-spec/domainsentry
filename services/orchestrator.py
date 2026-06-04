"""
Orchestrator Service (:8010)
Coordina la pipeline: legge il feed, chiama i servizi, pubblica eventi.
"""

import os, json, logging, time, threading
from datetime import datetime, timezone
from fastapi import FastAPI, APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import requests

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="Orchestrator", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("orchestrator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [ORCH] %(message)s")

# Service URLs (configurabili via env)
FEED_URL = os.environ.get("FEED_URL", "http://feed-manager:8000")
DNS_URL = os.environ.get("DNS_URL", "http://dns-intel:8001")
CERT_URL = os.environ.get("CERT_URL", "http://cert-intel:8002")
HTTP_URL = os.environ.get("HTTP_URL", "http://http-fingerprint:8003")
WHOIS_URL = os.environ.get("WHOIS_URL", "http://whois-intel:8004")
REP_URL = os.environ.get("REP_URL", "http://reputation:8005")
TWIST_URL = os.environ.get("TWIST_URL", "http://dnstwist-engine:8006")
CLASSIFY_URL = os.environ.get("CLASSIFY_URL", "http://classifier:8007")
EVENT_URL = os.environ.get("EVENT_URL", "http://event-publisher:8011")

TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", "120"))
PIPELINE_MAX_DURATION = int(os.environ.get("PIPELINE_MAX_DURATION", "7200"))  # 2h max

_lock = threading.Lock()
_running = False
_run_started = 0.0


@app.get("/health")
def health():
    return {"status": "healthy", "service": "orchestrator", "version": "4.0.0",
            "running": _running}


@router.get("/status", tags=["Pipeline"])
def status():
    """Stato operativo con health check di tutti i servizi."""
    services = {}
    for name, url in [("feed-manager", FEED_URL), ("dns-intel", DNS_URL),
                       ("cert-intel", CERT_URL), ("http-fingerprint", HTTP_URL),
                       ("whois-intel", WHOIS_URL), ("reputation", REP_URL),
                       ("dnstwist-engine", TWIST_URL), ("classifier", CLASSIFY_URL),
                       ("event-publisher", EVENT_URL)]:
        try:
            r = requests.get(f"{url}/health", timeout=5)
            services[name] = "healthy" if r.ok else f"HTTP {r.status_code}"
        except Exception as e:
            services[name] = f"unreachable: {e}"

    # Feed info
    try:
        r = requests.get(f"{FEED_URL}/feed/clients", timeout=5)
        clients = r.json().get("total", 0) if r.ok else 0
    except Exception:
        clients = 0

    return {
        "status": "operational" if all(v == "healthy" for v in services.values()) else "degraded",
        "timestamp": now_iso(),
        "running": _running,
        "clients": clients,
        "services": services
    }


class TriggerRequest(BaseModel):
    client: Optional[str] = None
    include_dnstwist: bool = False
    include_whois: bool = True
    include_reputation: bool = True


@router.post("/trigger", tags=["Pipeline"])
def trigger(req: TriggerRequest, background_tasks: BackgroundTasks):
    """Triggera la pipeline in background."""
    global _running, _run_started
    with _lock:
        # Reset se la pipeline è stale (durata > max)
        if _running and (time.time() - _run_started) > PIPELINE_MAX_DURATION:
            logger.warning("Pipeline stale, reset forzato")
            _running = False
        if _running:
            return JSONResponse(status_code=409,
                                content={"error": "Pipeline già in esecuzione",
                                         "running_since": _run_started})
        _running = True
        _run_started = time.time()

    background_tasks.add_task(_run_pipeline, req)
    return {"status": "triggered", "client": req.client or "all",
            "dnstwist": req.include_dnstwist, "timestamp": now_iso()}


def _run_pipeline(req: TriggerRequest):
    global _running
    _running = True
    start = time.time()

    try:
        # 1. Leggi feed
        feed_url = f"{FEED_URL}/feed/domains"
        if req.client:
            feed_url += f"?client={req.client}"
        r = requests.get(feed_url, timeout=10)
        r.raise_for_status()
        domains = r.json().get("domains", [])
        logger.info(f"Pipeline: {len(domains)} domini da processare")

        # Raggruppa per client
        by_client = {}
        for d in domains:
            c = d.get("client", "unknown")
            by_client.setdefault(c, []).append(d)

        all_events = []

        for client, client_domains in by_client.items():
            logger.info(f"━━ Client: {sanitize_log_input(client)} ({len(client_domains)} domini) ━━")

            # Carica whitelist
            try:
                wr = requests.get(f"{FEED_URL}/feed/whitelist?client={client}", timeout=5)
                whitelist = list(wr.json().get("whitelist", {}).keys()) if wr.ok else []
            except Exception:
                whitelist = []

            for entry in client_domains:
                domain = entry["domain"]
                if domain in whitelist:
                    logger.info(f"  {sanitize_log_input(domain)} — whitelisted, skip")
                    continue

                logger.info(f"  [CHECK] {sanitize_log_input(domain)}")
                intel = _gather_intelligence(domain, req)

                # Classify
                try:
                    cr = requests.post(f"{CLASSIFY_URL}/classify/variant", json={
                        "domain": domain, "fuzzer": entry.get("fuzzer", ""),
                        "dns": intel.get("dns"), "cert": intel.get("cert"),
                        "http": intel.get("http"), "whois": intel.get("whois"),
                        "reputation": intel.get("reputation")
                    }, timeout=10)
                    intel["classification"] = cr.json() if cr.ok else None
                except Exception as e:
                    logger.error(f"  Classification error: {e}")
                    intel["classification"] = None

                # Raccogli eventi
                if intel.get("classification"):
                    all_events.append({
                        "client": client, "domain": domain,
                        "classification": intel["classification"],
                        "intel_summary": {
                            "dns_a": bool(intel.get("dns", {}).get("records", {}).get("A")),
                            "dns_mx": bool(intel.get("dns", {}).get("records", {}).get("MX")),
                            "http_active": intel.get("http", {}).get("overall_status") == "active",
                            "cert_count": intel.get("cert", {}).get("ct_certificates", {}).get("total", 0),
                            "reputation_score": intel.get("reputation", {}).get("risk_score", 0),
                        }
                    })

            # dnstwist (opzionale)
            if req.include_dnstwist:
                targets = [d for d in client_domains if d.get("type") == "target"]
                for t in targets:
                    legit = t.get("legitimate", t["domain"])
                    logger.info(f"  [TWIST] {legit}")
                    try:
                        tr = requests.get(f"{TWIST_URL}/twist?domain={legit}", timeout=300)
                        if tr.ok:
                            twist_data = tr.json()
                            variant_count = twist_data.get('registered_variants', 0)
                            logger.info(f"  [TWIST] {variant_count} varianti")
                            # Aggiungi ogni nuova variante come evento
                            for variant in twist_data.get("variants", []):
                                all_events.append({
                                    "client": client,
                                    "domain": variant.get("domain", ""),
                                    "event_type": "dnstwist_variant_found",
                                    "classification": {
                                        "auto_classification": "needs_review",
                                        "rule": "dnstwist_discovery",
                                        "confidence": "low",
                                        "rationale": f"Variante {variant.get('fuzzer','')} di {legit}"
                                    },
                                    "intel_summary": {
                                        "dns_a": bool(variant.get("dns_a")),
                                        "dns_mx": bool(variant.get("dns_mx")),
                                        "fuzzer": variant.get("fuzzer", ""),
                                        "geoip": variant.get("geoip", ""),
                                    }
                                })
                    except Exception as e:
                        logger.error(f"  dnstwist error: {e}")

        # Pubblica eventi
        if all_events:
            try:
                requests.post(f"{EVENT_URL}/publish", json={"events": all_events}, timeout=10)
                logger.info(f"Pubblicati {len(all_events)} eventi")
            except Exception as e:
                logger.error(f"Event publish error: {e}")

        elapsed = round(time.time() - start, 2)
        logger.info(f"Pipeline completata in {elapsed}s — {len(all_events)} eventi")

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
    finally:
        _running = False


def _gather_intelligence(domain: str, req: TriggerRequest) -> dict:
    """Chiama i servizi di intelligence per un dominio."""
    intel = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}

    try:
        r = requests.get(f"{DNS_URL}/dns?domain={domain}&full=true&subdomains=true", timeout=TIMEOUT)
        intel["dns"] = r.json() if r.ok else None
    except Exception as e:
        logger.warning(f"  DNS error: {e}")

    try:
        r = requests.get(f"{CERT_URL}/cert?domain={domain}", timeout=TIMEOUT)
        intel["cert"] = r.json() if r.ok else None
    except Exception as e:
        logger.warning(f"  CERT error: {e}")

    try:
        r = requests.get(f"{HTTP_URL}/http?domain={domain}", timeout=TIMEOUT)
        intel["http"] = r.json() if r.ok else None
    except Exception as e:
        logger.warning(f"  HTTP error: {e}")

    if req.include_whois:
        try:
            r = requests.get(f"{WHOIS_URL}/whois?domain={domain}", timeout=TIMEOUT)
            intel["whois"] = r.json() if r.ok else None
        except Exception as e:
            logger.warning(f"  WHOIS error: {e}")

    if req.include_reputation:
        try:
            r = requests.get(f"{REP_URL}/reputation?domain={domain}", timeout=TIMEOUT)
            intel["reputation"] = r.json() if r.ok else None
        except Exception as e:
            logger.warning(f"  REP error: {e}")

    return intel

app.include_router(router)
