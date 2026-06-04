"""
Feed Manager Service (:8000)
Gestione liste domini e whitelist.
"""

import os, json, logging
from pathlib import Path
from fastapi import FastAPI, APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="Feed Manager", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("feed")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [FEED] %(message)s")

DATA_DIR = Path(os.environ.get("FEED_DATA", "/data/feed"))
FEED_FILE = DATA_DIR / "feed.json"
WHITELIST_DIR = DATA_DIR / "whitelists"


def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WHITELIST_DIR.mkdir(parents=True, exist_ok=True)


def _load_feed() -> dict:
    _ensure_dirs()
    if FEED_FILE.exists():
        with open(FEED_FILE) as f:
            return json.load(f)
    return {"domains": [], "last_updated": now_iso()}


def _save_feed(data: dict):
    """Atomic write: scrivi su tmp e rinomina per prevenire corruzione."""
    import tempfile
    data["last_updated"] = now_iso()
    tmp_path = FEED_FILE.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    tmp_path.rename(FEED_FILE)


def _safe_client_name(client: str) -> str:
    """Sanitizza il nome client per prevenire path traversal."""
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', client)
    if not sanitized or sanitized != client:
        raise HTTPException(400, f"Client name invalido: solo alfanumerici, trattini e underscore")
    return sanitized


def _load_whitelist(client: str) -> dict:
    client = _safe_client_name(client)
    _ensure_dirs()
    # Prova JSON prima
    json_path = WHITELIST_DIR / f"{client}.json"
    if json_path.exists():
        with open(json_path) as f:
            return json.load(f)
    # Fallback a txt
    txt_path = WHITELIST_DIR / f"{client}.txt"
    if txt_path.exists():
        return _parse_whitelist_txt(txt_path)
    return {"domains": {}}


def _save_whitelist(client: str, data: dict):
    client = _safe_client_name(client)
    _ensure_dirs()
    json_path = WHITELIST_DIR / f"{client}.json"
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)
    # Sync anche il txt
    txt_path = WHITELIST_DIR / f"{client}.txt"
    with open(txt_path, "w") as f:
        f.write(f"# Whitelist domini verificati — {client}\n")
        f.write("# Formato: dominio | motivo | data\n")
        for dom, info in sorted(data.get("domains", {}).items()):
            f.write(f"{dom} | {info.get('reason', '')} | {info.get('added', '')}\n")


def _parse_whitelist_txt(path: Path) -> dict:
    domains = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            dom = parts[0]
            reason = parts[1] if len(parts) > 1 else ""
            added = parts[2] if len(parts) > 2 else ""
            domains[dom] = {"reason": reason, "added": added, "added_by": "file"}
    return {"domains": domains}


@app.get("/health")
def health():
    return {"status": "healthy", "service": "feed-manager", "version": "4.0.0"}


# ── Feed domini ──

@router.get("/feed/domains", tags=["Feed"])
def get_domains(client: str = Query(None)):
    feed = _load_feed()
    domains = feed.get("domains", [])
    if client:
        domains = [d for d in domains if d.get("client") == client]
    return {"domains": domains, "total": len(domains), "last_updated": feed.get("last_updated")}


class DomainAdd(BaseModel):
    domain: str
    client: str
    legitimate: str
    type: str = "target"  # target | watchlist

    @field_validator("domain", "legitimate")
    @classmethod
    def validate_domain(cls, v):
        import re
        v = v.strip().lower()
        if not v:
            raise ValueError("Domain cannot be empty")
        if len(v) > 253:
            raise ValueError(f"Domain too long: {len(v)} chars (max 253)")
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', v):
            raise ValueError(f"Invalid domain format: {v}")
        return v

    @field_validator("client")
    @classmethod
    def validate_client(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Client name: only alphanumeric, hyphens and underscores")
        return v


@router.post("/feed/domains", tags=["Feed"])
def add_domain(entry: DomainAdd):
    feed = _load_feed()
    # Check duplicati
    if any(d["domain"] == entry.domain and d["client"] == entry.client
           for d in feed["domains"]):
        raise HTTPException(400, f"{entry.domain} già presente per {entry.client}")
    feed["domains"].append({
        "domain": entry.domain, "client": entry.client,
        "legitimate": entry.legitimate, "type": entry.type,
        "added": now_iso(), "source": "api"
    })
    _save_feed(feed)
    return {"status": "added", "domain": entry.domain}


@router.delete("/feed/domains/{domain}")
def remove_domain(domain: str, client: str = Query(None)):
    feed = _load_feed()
    before = len(feed["domains"])
    feed["domains"] = [d for d in feed["domains"]
                       if not (d["domain"] == domain and (not client or d["client"] == client))]
    if len(feed["domains"]) == before:
        raise HTTPException(404, f"{domain} non trovato")
    _save_feed(feed)
    return {"status": "removed", "domain": domain}


# ── Whitelist ──

@router.get("/feed/whitelist", tags=["Whitelist"])
def get_whitelist(client: str = Query(...)):
    wl = _load_whitelist(client)
    return {"client": client, "whitelist": wl.get("domains", {}),
            "total": len(wl.get("domains", {}))}


class WhitelistAdd(BaseModel):
    domain: str
    reason: str
    added_by: str = "api"


@router.post("/feed/whitelist", tags=["Whitelist"])
def add_whitelist(client: str = Query(...), entry: WhitelistAdd = ...):
    wl = _load_whitelist(client)
    wl.setdefault("domains", {})[entry.domain] = {
        "reason": entry.reason, "added_by": entry.added_by, "added": now_iso()
    }
    _save_whitelist(client, wl)
    return {"status": "whitelisted", "domain": entry.domain}


@router.delete("/feed/whitelist/{domain}")
def remove_whitelist(domain: str, client: str = Query(...)):
    wl = _load_whitelist(client)
    if domain not in wl.get("domains", {}):
        raise HTTPException(404, f"{domain} non in whitelist")
    del wl["domains"][domain]
    _save_whitelist(client, wl)
    return {"status": "removed", "domain": domain}


# ── Clients listing (derived from feed) ──

@router.get("/feed/clients", tags=["Feed"])
def list_clients():
    feed = _load_feed()
    clients = {}
    for d in feed.get("domains", []):
        c = d.get("client", "unknown")
        if c not in clients:
            clients[c] = {"name": c, "targets": [], "watchlist": [], "legitimate": d.get("legitimate")}
        if d.get("type") == "target":
            clients[c]["targets"].append(d["domain"])
        else:
            clients[c]["watchlist"].append(d["domain"])
    return {"clients": list(clients.values()), "total": len(clients)}

app.include_router(router)
