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
import threading
import time
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Import routers from all services
from services.dns_intel import router as dns_router
from services.cert_intel import router as cert_router
from services.http_fingerprint import router as http_router
from services.whois_intel import router as whois_router
from services import whois_intel as _whois_intel
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


# ── PERF-04: capacità dei collettori ──
# I gestori sincroni di tutti i servizi (collettori, dashboard, login, `/health`) condividono i 40 thread del pool di
# anyio. Richieste lente ai cinque collettori li occupavano tutti, e il resto del servizio aspettava. Il filtro ammette
# al più COLLECTOR_CAPACITY_TOTAL richieste ai collettori insieme, e per collettore i posti di
# COLLECTOR_CAPACITY_EACH: le altre ricevono subito un 503, senza prendere un thread. Il posto torna libero quando il
# gestore finisce davvero (`await` dell'app), non quando il chiamante smette di aspettare: il thread è occupato
# fino ad allora. Costanti di modulo, come le soglie di SEC-35.
COLLECTOR_PATHS = {"/dns": "dns", "/cert": "cert", "/http": "http", "/whois": "whois", "/reputation": "reputation"}
COLLECTOR_CAPACITY_TOTAL = 20


def _whois_places():
    """Ogni `/whois` ammesso prenota un turno distanziato di WHOIS_DELAY e oltre WHOIS_MAX_WAIT_S risponde senza
    raccogliere (PERF-02): con più richieste in coda di quante ne stiano nel tetto d'attesa, anche quella della
    scansione resterebbe senza turno. I posti lasciano due turni di margine: 4 con i valori di default."""
    if _whois_intel.WHOIS_DELAY <= 0:
        return 8
    return max(1, min(8, int(_whois_intel.WHOIS_MAX_WAIT_S // _whois_intel.WHOIS_DELAY) - 2))


COLLECTOR_CAPACITY_EACH = {"dns": 8, "cert": 8, "http": 8, "whois": _whois_places(), "reputation": 4}


class _CollectorCapacity:
    """Posti occupati dalle richieste ai collettori, in tutto e per collettore."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self._total = 0
            self._each = dict.fromkeys(COLLECTOR_CAPACITY_EACH, 0)
            self._refused, self._last_log = {}, float("-inf")

    def take(self, collector):
        with self._lock:
            if self._total >= COLLECTOR_CAPACITY_TOTAL or self._each[collector] >= COLLECTOR_CAPACITY_EACH[collector]:
                return False
            self._total += 1
            self._each[collector] += 1
            return True

    def give_back(self, collector):
        with self._lock:
            self._total -= 1
            self._each[collector] -= 1

    def refused(self, collector, now):
        """Conta un rifiuto; restituisce il conteggio da loggare al più una volta ogni 10 s, altrimenti None: sotto
        un flood una riga per rifiuto riempirebbe il log."""
        with self._lock:
            self._refused[collector] = self._refused.get(collector, 0) + 1
            if now - self._last_log < 10:
                return None
            self._last_log, counts, self._refused = now, self._refused, {}
            return counts

    def in_use(self):
        with self._lock:
            return self._total


_COLLECTOR_CAPACITY = _CollectorCapacity()


def _route_path(scope):
    """Il percorso come lo instrada Starlette, senza il `root_path`: dietro un prefisso (`--root-path`) il percorso
    intero non coinciderebbe e il filtro si spegnerebbe in silenzio."""
    path, root = scope.get("path", ""), scope.get("root_path", "")
    if not root or not path.startswith(root):
        return path
    if path == root:
        return ""
    # Come Starlette: il prefisso si toglie solo al confine di `/` (`root_path=/w` lascia `/whois` intero).
    return path[len(root):] if path[len(root)] == "/" else path


class CollectorCapacityMiddleware:
    """Filtro ASGI: prima del pool di thread, quindi un rifiuto non occupa un thread."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        collector = COLLECTOR_PATHS.get(_route_path(scope)) if scope["type"] == "http" else None
        if collector is None:
            await self.app(scope, receive, send)
            return
        if not _COLLECTOR_CAPACITY.take(collector):
            counts = _COLLECTOR_CAPACITY.refused(collector, time.monotonic())
            if counts:
                logger.warning("Capacità dei collettori esaurita, richieste rifiutate con 503: %s",
                               ", ".join(f"/{name} {n}" for name, n in sorted(counts.items())))
            await JSONResponse({"error": "collector capacity exhausted, retry later"}, status_code=503,
                               headers={"Retry-After": "5"})(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            _COLLECTOR_CAPACITY.give_back(collector)


app.add_middleware(CollectorCapacityMiddleware)

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
        "version": "4.21.0",
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
        "version": "4.21.0",
        "mode": "unified",
        "case_manager": "enabled" if ENABLE_CASE_MANAGER else "disabled",
        "docs": "/docs",
        "endpoints": endpoints
    }
