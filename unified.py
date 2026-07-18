"""
DomainSentry — Unified App
===========================
All services on a single port. One container, one command.

    docker compose up -d
    curl http://localhost:8000/docs

For production with separate containers:
    docker compose -f docker-compose.prod.yml up -d
"""

import os
import logging
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Import routers from all services
from services.dns_intel import router as dns_router
from services.cert_intel import router as cert_router
from services.http_fingerprint import router as http_router
from services.whois_intel import router as whois_router
from services.reputation import router as rep_router
from services.dnstwist_engine import router as twist_router
from services.classifier import router as classify_router
from services.feed_manager import router as feed_router
from services.orchestrator import router as orch_router
from services.event_publisher import router as events_router

# Optional: case-manager (stateful, requires CASES_DB volume).
# Enable by setting ENABLE_CASE_MANAGER=true
ENABLE_CASE_MANAGER = os.environ.get("ENABLE_CASE_MANAGER", "false").lower() == "true"

from shared.security import apply_security

logger = logging.getLogger("domainsentry")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [SENTRY] %(message)s")

app = FastAPI(
    title="DomainSentry",
    version="4.0.0",
    description="Self-hosted domain intelligence platform for detecting "
                "typosquatting, brand impersonation, and domain compromise.",
    openapi_tags=[
        {"name": "Intelligence", "description": "Domain enrichment endpoints"},
        {"name": "Classification", "description": "Auto-classification and baseline diffing"},
        {"name": "Feed", "description": "Domain lists and whitelist management"},
        {"name": "Pipeline", "description": "Orchestration and monitoring"},
        {"name": "Events", "description": "SOC event output"},
    ]
)
apply_security(app)

# ── Mount all routers ──
app.include_router(dns_router, tags=["Intelligence"])
app.include_router(cert_router, tags=["Intelligence"])
app.include_router(http_router, tags=["Intelligence"])
app.include_router(whois_router, tags=["Intelligence"])
app.include_router(rep_router, tags=["Intelligence"])
app.include_router(twist_router, tags=["Intelligence"])
app.include_router(classify_router, tags=["Classification"])
app.include_router(feed_router, tags=["Feed"])
app.include_router(orch_router, tags=["Pipeline"])
app.include_router(events_router, tags=["Events"])

if ENABLE_CASE_MANAGER:
    from services.case_manager import router as case_router
    app.include_router(case_router)
    logger.info("Case Manager enabled (auth + case management)")

    # Dashboard depends on the case-manager API; mount it alongside.
    # Can be disabled independently with ENABLE_DASHBOARD=false.
    if os.environ.get("ENABLE_DASHBOARD", "true").lower() == "true":
        from services.dashboard import router as dash_router
        app.include_router(dash_router)
        logger.info("Dashboard enabled at /dashboard")


@app.get("/health")
def health():
    """Unified health check."""
    return {
        "status": "healthy",
        "service": "domainsentry-unified",
        "version": "4.20.1",
        "mode": "unified",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def root():
    """Welcome endpoint with service index."""
    endpoints = {
        "intelligence": {
            "dns": "/dns?domain=example.com&full=true",
            "cert": "/cert?domain=example.com",
            "http": "/http?domain=example.com",
            "whois": "/whois?domain=example.com",
            "reputation": "/reputation?domain=example.com",
            "twist": "/twist?domain=example.com",
        },
        "classification": {
            "classify_variant": "POST /classify/variant",
            "classify_batch": "POST /classify/batch",
            "diff": "POST /diff",
        },
        "feed": {
            "domains": "/feed/domains",
            "whitelist": "/feed/whitelist?client=NAME",
            "clients": "/feed/clients",
        },
        "pipeline": {
            "status": "/status",
            "trigger": "POST /trigger",
        },
        "events": {
            "list": "/events",
            "publish": "POST /publish",
        }
    }
    if ENABLE_CASE_MANAGER:
        endpoints["case_management"] = {
            "login": "POST /auth/login",
            "me": "/auth/me",
            "users": "POST /users  (admin)",
            "cases": "/cases",
            "ingest": "POST /cases/ingest",
            "assign": "POST /cases/{id}/assign",
            "whitelist": "POST /cases/{id}/whitelist",
            "summary": "/summary",
        }
        if os.environ.get("ENABLE_DASHBOARD", "true").lower() == "true":
            endpoints["dashboard"] = {"ui": "/dashboard"}
    return {
        "name": "DomainSentry",
        "version": "4.20.1",
        "mode": "unified",
        "case_manager": "enabled" if ENABLE_CASE_MANAGER else "disabled",
        "docs": "/docs",
        "endpoints": endpoints
    }
