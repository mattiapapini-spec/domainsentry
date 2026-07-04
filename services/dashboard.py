"""
Dashboard Service (:8013)
=========================
Serves the SOC triage dashboard — a single-file HTML/CSS/JS page that talks
to the case-manager API (same origin in unified mode).

Opt-in, and useless without the case-manager. In unified mode it is mounted
alongside the case-manager; in production it runs as its own container behind
the same origin / reverse proxy as the case-manager.

No external dependencies: the page is fully self-contained (no CDN, no web
fonts), which is required on locked-down networks.
"""

import os
import logging
from pathlib import Path
from fastapi import FastAPI, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

from shared.security import apply_security

logger = logging.getLogger("dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DASH] %(message)s")

app = FastAPI(title="DomainSentry Dashboard", version="4.13.0")
apply_security(app)
router = APIRouter()

_HTML_PATH = Path(__file__).parent / "dashboard_app.html"
# Load once at import; small file, served many times.
try:
    _HTML = _HTML_PATH.read_text(encoding="utf-8")
except FileNotFoundError:
    _HTML = "<h1>Dashboard asset missing</h1>"


@app.get("/health")
def health():
    return {"status": "healthy", "service": "dashboard", "version": "4.13.0"}


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return HTMLResponse(_HTML)


app.include_router(router)
