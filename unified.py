"""
DomainSentry — Unified App
===========================
All services on a single port. One container, one command.

    docker compose up -d
    curl http://localhost:8000/docs

For production with separate containers:
    docker compose -f docker-compose.prod.yml up -d
"""

import hmac
import os
import logging
import secrets
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
from services.reputation import router as rep_router
from services.dnstwist_engine import router as twist_router
from services.classifier import router as classify_router
from services.feed_manager import router as feed_router
from services.orchestrator import router as orch_router
from services import orchestrator as _orchestrator
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
COLLECTOR_CAPACITY_EACH = {"dns": 8, "cert": 8, "http": 8, "whois": 8, "reputation": 4}


# ── PERF-08 e variante B2: la riserva della scansione ──
# Col solo tetto un flood anonimo occupava anche i posti che servono alla scansione legittima. SCAN_RESERVE posti sono
# della scansione dell'orchestrator, riconosciuta dall'intestazione SCAN_HEADER col contrassegno casuale SCAN_TOKEN,
# nuovo a ogni avvio del processo e mai esposto (l'orchestrator lo manda dalla propria sessione HTTP, sotto); con la
# riserva piena la scansione usa i posti anonimi. Variante B2 (decisione di Mat): una richiesta della scansione più
# vecchia di SCAN_ABANDON_AFTER_S, il `SERVICE_TIMEOUT` dell'orchestrator, è già stata abbandonata, perché
# l'orchestrator rinuncia sempre a quella soglia, ma il suo thread è ancora occupato. Passa in un conto a parte con al
# più SCAN_ABANDONED_MAX posti, con una riga nel log, e la riserva torna alla scansione viva. In tutto non sono mai in
# corso più di COLLECTOR_CAPACITY_TOTAL + SCAN_RESERVE + SCAN_ABANDONED_MAX richieste ai collettori (32 su 40 thread).
SCAN_HEADER = "X-DomainSentry-Scan"
SCAN_TOKEN = secrets.token_hex(32)
SCAN_RESERVE = 8
SCAN_ABANDONED_MAX = 4
SCAN_ABANDON_AFTER_S = _orchestrator.TIMEOUT
_orchestrator._session.headers[SCAN_HEADER] = SCAN_TOKEN
_SCAN_HEADER_KEY = SCAN_HEADER.lower().encode()


class _Place:
    """Un posto occupato: il collettore, il conto in cui sta (anonymous, reserve, abandoned) e quando è iniziato."""

    __slots__ = ("collector", "bucket", "started")

    def __init__(self, collector, bucket, started):
        self.collector, self.bucket, self.started = collector, bucket, started


class _CollectorCapacity:
    """Posti occupati dalle richieste ai collettori: anonimi (in tutto e per collettore), della riserva della
    scansione e della scansione abbandonata."""

    def __init__(self):
        self._lock = threading.Lock()
        self.clock = time.monotonic
        self.reset()

    def reset(self):
        with self._lock:
            self._total = 0
            self._each = dict.fromkeys(COLLECTOR_CAPACITY_EACH, 0)
            self._reserve = []
            self._abandoned = 0
            self._refused, self._last_log = {}, float("-inf")

    def _take_anonymous(self, collector, now):
        """Con `_lock` preso."""
        if self._total >= COLLECTOR_CAPACITY_TOTAL or self._each[collector] >= COLLECTOR_CAPACITY_EACH[collector]:
            return None
        self._total += 1
        self._each[collector] += 1
        return _Place(collector, "anonymous", now)

    def take(self, collector, scan=False):
        """Il posto ottenuto (o None) e i posti della riserva appena passati fra gli abbandonati, da loggare."""
        with self._lock:
            now = self.clock()
            if not scan:
                return self._take_anonymous(collector, now), []
            moved = []
            for place in list(self._reserve):
                if self._abandoned >= SCAN_ABANDONED_MAX:
                    break
                if now - place.started > SCAN_ABANDON_AFTER_S:
                    self._reserve.remove(place)
                    place.bucket = "abandoned"
                    self._abandoned += 1
                    moved.append((place.collector, now - place.started))
            if len(self._reserve) < SCAN_RESERVE:
                place = _Place(collector, "reserve", now)
                self._reserve.append(place)
                return place, moved
            return self._take_anonymous(collector, now), moved

    def give_back(self, place):
        with self._lock:
            if place.bucket == "anonymous":
                self._total -= 1
                self._each[place.collector] -= 1
            elif place.bucket == "reserve":
                self._reserve.remove(place)
            else:
                self._abandoned -= 1

    def refused(self, collector):
        """Conta un rifiuto; restituisce il conteggio da loggare al più una volta ogni 10 s, altrimenti None: sotto
        un flood una riga per rifiuto riempirebbe il log."""
        with self._lock:
            now = self.clock()
            self._refused[collector] = self._refused.get(collector, 0) + 1
            if now - self._last_log < 10:
                return None
            self._last_log, counts, self._refused = now, self._refused, {}
            return counts

    def in_use(self):
        with self._lock:
            return self._total + len(self._reserve) + self._abandoned


_COLLECTOR_CAPACITY = _CollectorCapacity()


def _is_scan(scope):
    for key, value in scope.get("headers") or ():
        if key == _SCAN_HEADER_KEY:
            return hmac.compare_digest(value, SCAN_TOKEN.encode())
    return False


class CollectorCapacityMiddleware:
    """Filtro ASGI: prima del pool di thread, quindi un rifiuto non occupa un thread."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        collector = COLLECTOR_PATHS.get(scope.get("path")) if scope["type"] == "http" else None
        if collector is None:
            await self.app(scope, receive, send)
            return
        place, moved = _COLLECTOR_CAPACITY.take(collector, scan=_is_scan(scope))
        for name, age in moved:
            logger.warning("Richiesta della scansione abbandonata dall'orchestrator: /%s in corso da %.0f s, "
                           "spostata fuori dalla riserva", name, age)
        if place is None:
            counts = _COLLECTOR_CAPACITY.refused(collector)
            if counts:
                logger.warning("Capacità dei collettori esaurita, richieste rifiutate con 503: %s",
                               ", ".join(f"/{name} {n}" for name, n in sorted(counts.items())))
            await JSONResponse({"error": "collector capacity exhausted, retry later"}, status_code=503,
                               headers={"Retry-After": "5"})(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            _COLLECTOR_CAPACITY.give_back(place)


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
