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
from shared import intel_store

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

# Auto case ingestion (opt-in). When true, each pipeline event is also pushed
# to the case-manager as a manageable case. Requires the case-manager running
# and a service token with manage_cases permission.
CASE_INGEST = os.environ.get("CASE_INGEST", "false").lower() == "true"
CASE_MANAGER_URL = os.environ.get("CASE_MANAGER_URL", "http://case-manager:8012")
CASE_INGEST_TOKEN = os.environ.get("CASE_INGEST_TOKEN", "")

# Intelligence persistence (opt-in): store full per-domain snapshot + diff history
# for the dashboard Intelligence tab.
INTEL_STORE = os.environ.get("INTEL_STORE", "false").lower() == "true"

# Map auto_classification → case severity
CLASSIFICATION_SEVERITY = {
    "phishing": "CRITICAL", "phishing-kit": "CRITICAL", "malware": "CRITICAL",
    "redirect-kit": "HIGH", "redirect-chain": "HIGH", "suspicious": "HIGH",
    "needs_review": "MEDIUM", "mx_only": "MEDIUM",
    "parking": "LOW", "inactive": "LOW", "benign": "LOW", "legitimate": "LOW",
}

TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", "45"))
PIPELINE_MAX_DURATION = int(os.environ.get("PIPELINE_MAX_DURATION", "7200"))  # 2h max

_lock = threading.Lock()
_running = False
_run_started = 0.0

# ── Pipeline progress + log telemetry (read via /progress) ──
# Updated as the pipeline advances so the dashboard can show real progress,
# not a fake animation. _progress holds structured state; _log_buffer holds
# the last N log lines of the current run.
_MAX_LOG_LINES = 200
_progress = {
    "running": False,
    "phase": "idle",          # idle | starting | scanning | dnstwist | done | error
    "client": None,
    "current_domain": None,
    "done": 0,                # domains processed so far
    "total": 0,               # domains known to process (grows as dnstwist discovers)
    "started_at": None,
    "finished_at": None,
    "events": 0,
}
_log_buffer = []

def _progress_set(**kw):
    """Thread-safe update of the progress state."""
    with _lock:
        _progress.update(kw)

def _progress_reset(client, total):
    with _lock:
        _progress.update({
            "running": True, "phase": "starting", "client": client or "all",
            "current_domain": None, "done": 0, "total": total,
            "started_at": now_iso(), "finished_at": None, "events": 0,
        })
        _log_buffer.clear()

def _plog(msg):
    """Append a line to the in-memory log buffer (and the normal logger)."""
    logger.info(msg)
    with _lock:
        _log_buffer.append({"ts": now_iso(), "msg": sanitize_log_input(str(msg))})
        if len(_log_buffer) > _MAX_LOG_LINES:
            del _log_buffer[0:len(_log_buffer) - _MAX_LOG_LINES]

# Shared session with connection pooling (reuses TCP/TLS connections)
_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


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
            r = _session.get(f"{url}/health", timeout=5)
            services[name] = "healthy" if r.ok else f"HTTP {r.status_code}"
        except Exception as e:
            services[name] = f"unreachable: {e}"

    # Feed info
    try:
        r = _session.get(f"{FEED_URL}/feed/clients", timeout=5)
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


@router.get("/progress", tags=["Pipeline"])
def progress(include_log: bool = True):
    """
    Real progress of the running (or last) pipeline: phase, current domain,
    done/total counts, plus the recent log lines. Used by the dashboard's
    Scan progress view. Reflects actual pipeline state, not an estimate.
    """
    with _lock:
        state = dict(_progress)
        state["log"] = list(_log_buffer) if include_log else []
    # Derive a percentage when we have a total to compare against
    total = state.get("total") or 0
    done = state.get("done") or 0
    state["percent"] = round(100 * done / total) if total > 0 else (100 if state["phase"] == "done" else 0)
    return state


class TriggerRequest(BaseModel):
    client: Optional[str] = None
    include_dnstwist: bool = False
    include_whois: bool = True
    include_reputation: bool = True
    scope: str = "all"          # all | target | watchlist — which feed domains to scan
    variant_intel: bool = False  # gather full intel on dnstwist variants (slower, opt-in)


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
            "scope": req.scope, "dnstwist": req.include_dnstwist,
            "variant_intel": req.variant_intel, "timestamp": now_iso()}


def _persist_intel(client: str, domain: str, legitimate: str, intel: dict):
    """
    Diff the current intel against the stored snapshot, then persist:
    save the new snapshot (overwrite) and append the diff to history (deltas only).
    Uses the classifier's /diff endpoint for the comparison.
    """
    # Build the comparable intel object (exclude classification — that's separate)
    current = {
        "dns": intel.get("dns"), "cert": intel.get("cert"),
        "http": intel.get("http"), "whois": intel.get("whois"),
        "reputation": intel.get("reputation"),
    }
    prev = intel_store.load_snapshot(client, domain)
    prev_intel = (prev or {}).get("intel") if prev else None

    # Only diff if we have a previous snapshot to compare against
    if prev_intel:
        try:
            dr = _session.post(f"{CLASSIFY_URL}/diff", json={
                "domain": domain, "client": client, "legitimate": legitimate,
                "baseline": prev_intel, "current": current,
            }, timeout=15)
            if dr.ok:
                diff = dr.json()
                if intel_store.append_history(client, domain, diff):
                    logger.info(f"  intel diff: {diff.get('alert_count',0)} change(s) — {sanitize_log_input(diff.get('max_severity','CLEAN'))}")
        except Exception as e:
            logger.warning(f"  diff error: {sanitize_log_input(str(e))}")

    intel_store.save_snapshot(client, domain, current)


def _ingest_cases(events: list):
    """
    Push pipeline events to the case-manager as cases (opt-in).
    Each event's classification becomes a case keyed by (domain, client).
    The case-manager handles create/update/reopen logic. Fail-safe: a failure
    here is logged but never breaks the pipeline.
    """
    if not CASE_INGEST_TOKEN:
        logger.warning("CASE_INGEST enabled but CASE_INGEST_TOKEN missing — skipping case ingest")
        return
    headers = {"Authorization": f"Bearer {CASE_INGEST_TOKEN}"}
    ok = 0
    for ev in events:
        cls = ev.get("classification") or {}
        category = cls.get("auto_classification", "needs_review")
        payload = {
            "domain": ev.get("domain"),
            "client": ev.get("client"),
            "classification": category,
            "confidence": cls.get("confidence"),
            "severity": CLASSIFICATION_SEVERITY.get(category, "MEDIUM"),
            "rationale": cls.get("rationale"),
        }
        try:
            r = _session.post(f"{CASE_MANAGER_URL}/cases/ingest",
                              json=payload, headers=headers, timeout=10)
            if r.ok:
                ok += 1
            elif r.status_code in (401, 403):
                logger.error(f"Case ingest auth failed (HTTP {r.status_code}) — check CASE_INGEST_TOKEN/permissions")
                return  # token bad for all; stop early
        except Exception as e:
            logger.warning(f"Case ingest error for {ev.get('domain')}: {sanitize_log_input(str(e))}")
    logger.info(f"Case ingest: {ok}/{len(events)} events → cases")


def _run_pipeline(req: TriggerRequest):
    global _running
    _running = True
    start = time.time()
    _progress_reset(req.client, 0)

    try:
        # 1. Leggi feed
        feed_url = f"{FEED_URL}/feed/domains"
        if req.client:
            feed_url += f"?client={req.client}"
        r = _session.get(feed_url, timeout=10)
        r.raise_for_status()
        domains = r.json().get("domains", [])
        # Scope filter: restrict to target-only or watchlist-only if requested
        scope = (req.scope or "all").lower()
        if scope in ("target", "watchlist"):
            domains = [d for d in domains if d.get("type", "target") == scope]
            _plog(f"Scope '{scope}': {len(domains)} domini dopo il filtro")

        _plog(f"Pipeline: {len(domains)} domini da processare")
        _progress_set(total=len(domains), phase="scanning")

        # Raggruppa per client
        by_client = {}
        for d in domains:
            c = d.get("client", "unknown")
            by_client.setdefault(c, []).append(d)

        all_events = []

        for client, client_domains in by_client.items():
            _plog(f"━━ Client: {client} ({len(client_domains)} domini) ━━")
            _progress_set(client=client)

            # Carica whitelist
            try:
                wr = _session.get(f"{FEED_URL}/feed/whitelist?client={client}", timeout=5)
                whitelist = list(wr.json().get("whitelist", {}).keys()) if wr.ok else []
            except Exception:
                whitelist = []

            for entry in client_domains:
                domain = entry["domain"]
                if domain in whitelist:
                    _plog(f"  {domain} — whitelisted, skip")
                    with _lock:
                        _progress["done"] += 1
                    continue

                _plog(f"  [CHECK] {domain}")
                _progress_set(current_domain=domain)
                intel = _gather_intelligence(domain, req)

                # Classify
                try:
                    cr = _session.post(f"{CLASSIFY_URL}/classify/variant", json={
                        "domain": domain, "fuzzer": entry.get("fuzzer", ""),
                        "dns": intel.get("dns"), "cert": intel.get("cert"),
                        "http": intel.get("http"), "whois": intel.get("whois"),
                        "reputation": intel.get("reputation")
                    }, timeout=10)
                    intel["classification"] = cr.json() if cr.ok else None
                except Exception as e:
                    logger.error(f"  Classification error: {e}")
                    intel["classification"] = None

                # Persist full intel snapshot + baseline diff history (opt-in).
                # Fail-safe: storage/diff errors never break the pipeline.
                if INTEL_STORE:
                    try:
                        _persist_intel(client, domain, entry.get("legitimate", domain), intel)
                    except Exception as e:
                        logger.warning(f"  intel persist error: {sanitize_log_input(str(e))}")

                # Raccogli eventi
                if intel.get("classification"):
                    all_events.append({
                        "client": client, "domain": domain,
                        "classification": intel["classification"],
                        "intel_summary": {
                            "dns_a": bool((intel.get("dns") or {}).get("records", {}).get("A")),
                            "dns_mx": bool((intel.get("dns") or {}).get("records", {}).get("MX")),
                            "http_active": (intel.get("http") or {}).get("overall_status") == "active",
                            "cert_count": (intel.get("cert") or {}).get("ct_certificates", {}).get("total", 0),
                            "reputation_score": (intel.get("reputation") or {}).get("risk_score", 0),
                        }
                    })

                with _lock:
                    _progress["done"] += 1

            # dnstwist (opzionale)
            if req.include_dnstwist:
                _progress_set(phase="dnstwist", current_domain=None)
                # Run dnstwist once per DISTINCT legitimate domain, not once per
                # target: multiple targets of the same client typically share the
                # same legitimate (e.g. 3 Kedrion targets all map to kedrion.com),
                # and dnstwist on the same legit yields identical variants — running
                # it per-target would repeat the whole discovery + variant-intel pass
                # N times (wasted work and external API calls).
                legits = []
                seen_legit = set()
                for d in client_domains:
                    if d.get("type") != "target":
                        continue
                    lg = d.get("legitimate", d["domain"])
                    if lg not in seen_legit:
                        seen_legit.add(lg)
                        legits.append(lg)
                for legit in legits:
                    _plog(f"  [TWIST] {legit}")
                    try:
                        tr = _session.get(f"{TWIST_URL}/twist?domain={legit}", timeout=300)
                        if tr.ok:
                            twist_data = tr.json()
                            variant_count = twist_data.get('registered_variants', 0)
                            logger.info(f"  [TWIST] {variant_count} varianti")
                            # Aggiungi ogni nuova variante come evento
                            for variant in twist_data.get("variants", []):
                                vdomain = variant.get("domain", "")
                                event = {
                                    "client": client,
                                    "domain": vdomain,
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
                                }

                                # Opt-in: gather FULL intel for registered variants so they
                                # can be triaged (tp/fp) on real data, not just the name.
                                # Only variants that resolve (A or MX) are worth the heavy
                                # pass; unregistered permutations are skipped.
                                if req.variant_intel and vdomain and (variant.get("dns_a") or variant.get("dns_mx")):
                                    logger.info(f"    [TWIST-INTEL] {sanitize_log_input(vdomain)}")
                                    try:
                                        vintel = _gather_intelligence(vdomain, req)
                                        _persist_intel(client, vdomain, legit, vintel)
                                        # Surface key signals in the event summary too
                                        vdns = (vintel.get("dns") or {}).get("records", {})
                                        vhttp = vintel.get("http") or {}
                                        vcert = (vintel.get("cert") or {}).get("ct_certificates", {})
                                        event["intel_summary"].update({
                                            "dns_a": bool(vdns.get("A")),
                                            "dns_mx": bool(vdns.get("MX")),
                                            "http_active": vhttp.get("overall_status") == "active",
                                            "cert_count": vcert.get("total", 0),
                                            "intel_collected": True,
                                        })
                                    except Exception as e:
                                        logger.warning(f"    [TWIST-INTEL] {sanitize_log_input(vdomain)} error: {sanitize_log_input(str(e))}")

                                all_events.append(event)
                    except Exception as e:
                        logger.error(f"  dnstwist error: {e}")

        # Pubblica eventi
        if all_events:
            try:
                _session.post(f"{EVENT_URL}/publish", json={"events": all_events}, timeout=10)
                _plog(f"Pubblicati {len(all_events)} eventi")
            except Exception as e:
                logger.error(f"Event publish error: {e}")

            # Ingest automatico nei case (opt-in via CASE_INGEST=true).
            # Trasforma ogni evento in un case gestibile dal case-manager.
            # Fail-safe: un errore qui non compromette la pipeline.
            if CASE_INGEST:
                _ingest_cases(all_events)

        elapsed = round(time.time() - start, 2)
        _plog(f"Pipeline completata in {elapsed}s — {len(all_events)} eventi")
        _progress_set(phase="done", current_domain=None, finished_at=now_iso(),
                      events=len(all_events), running=False)

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        _progress_set(phase="error", current_domain=None, finished_at=now_iso(), running=False)
    finally:
        _running = False


def _fetch_service(name: str, url: str) -> tuple:
    """Single service fetch, returns (name, result_or_None)."""
    try:
        r = _session.get(url, timeout=TIMEOUT)
        return (name, r.json() if r.ok else None)
    except Exception as e:
        logger.warning(f"  {name} error: {sanitize_log_input(str(e))}")
        return (name, None)


def _gather_intelligence(domain: str, req: TriggerRequest) -> dict:
    """
    Chiama i servizi di intelligence in PARALLELO.
    DNS + Cert + HTTP + WHOIS + Reputation girano concorrentemente:
    il tempo totale è max(componenti) invece di sum(componenti).
    """
    from concurrent.futures import ThreadPoolExecutor

    intel = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}

    # Costruisci la lista dei task da eseguire
    tasks = [
        ("dns", f"{DNS_URL}/dns?domain={domain}&full=true&subdomains=true"),
        ("cert", f"{CERT_URL}/cert?domain={domain}"),
        ("http", f"{HTTP_URL}/http?domain={domain}"),
    ]
    if req.include_whois:
        tasks.append(("whois", f"{WHOIS_URL}/whois?domain={domain}"))
    if req.include_reputation:
        tasks.append(("reputation", f"{REP_URL}/reputation?domain={domain}"))

    # Esegui in parallelo (guard contro tasks vuoto)
    with ThreadPoolExecutor(max_workers=max(len(tasks), 1)) as executor:
        futures = [executor.submit(_fetch_service, name, url) for name, url in tasks]
        for future in futures:
            name, result = future.result()
            intel[name] = result

    return intel


@router.get("/intel", tags=["Intelligence"])
def get_domain_intel(client: str, domain: str):
    """
    Full intelligence for a domain: current snapshot + baseline diff history.
    Populates the dashboard Intelligence tab. Requires INTEL_STORE enabled.
    """
    if not INTEL_STORE:
        return JSONResponse(status_code=404,
                            content={"error": "intel store disabled (set INTEL_STORE=true)"})
    return intel_store.get_intel(client, domain)


app.include_router(router)
