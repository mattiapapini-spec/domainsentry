"""
Event Publisher Service (:8011)
Instrada SOC events verso consumatori: file, Zabbix, SOAR, SMTP, webhook.
"""

import os, json, logging
from pathlib import Path
from fastapi import FastAPI, APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="Event Publisher", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("events")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [EVENT] %(message)s")

EVENTS_DIR = Path(os.environ.get("EVENTS_DIR", "/data/events"))
FILE_ENABLED = os.environ.get("TARGET_FILE_ENABLED", "true").lower() == "true"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_ENABLED = os.environ.get("TARGET_WEBHOOK_ENABLED", "false").lower() == "true"


@app.get("/health")
def health():
    return {"status": "healthy", "service": "event-publisher", "version": "4.0.0",
            "targets": {"file": FILE_ENABLED, "webhook": WEBHOOK_ENABLED}}


class PublishRequest(BaseModel):
    events: list[dict]


@router.post("/publish", tags=["Events"])
def publish(req: PublishRequest):
    """Pubblica eventi verso tutti i target configurati."""
    logger.info(f"Pubblicazione {len(req.events)} eventi")
    results = {"published": len(req.events), "targets": []}

    # File NDJSON
    if FILE_ENABLED:
        try:
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            ndjson_path = EVENTS_DIR / "soc_events.ndjson"
            with open(ndjson_path, "a") as f:
                for event in req.events:
                    event["_published_at"] = now_iso()
                    f.write(json.dumps(event) + "\n")
            results["targets"].append("file")
            logger.info(f"  File: {len(req.events)} righe → {ndjson_path}")
        except Exception as e:
            logger.error(f"  File error: {e}")

    # Latest snapshot
    try:
        latest_path = EVENTS_DIR / "soc_events_latest.json"
        with open(latest_path, "w") as f:
            json.dump({"timestamp": now_iso(), "count": len(req.events),
                       "events": req.events}, f, indent=2)
    except Exception as e:
        logger.error(f"  Latest snapshot error: {e}")

    # Webhook (Slack/Teams)
    if WEBHOOK_ENABLED and WEBHOOK_URL:
        try:
            import requests as req_lib
            for event in req.events:
                domain = event.get("domain", "?")
                client = event.get("client", "?")
                classification = event.get("classification", {})
                cat = classification.get("auto_classification", "unknown")
                confidence = classification.get("confidence", "?")

                payload = {
                    "text": f"🔍 *Domain Intelligence Alert*\n"
                            f"Client: {client} | Domain: `{domain}`\n"
                            f"Classification: *{cat}* ({confidence})\n"
                            f"Rule: {classification.get('rule', '?')}"
                }
                req_lib.post(WEBHOOK_URL, json=payload, timeout=10)
            results["targets"].append("webhook")
            logger.info(f"  Webhook: {len(req.events)} eventi inviati")
        except Exception as e:
            logger.error(f"  Webhook error: {e}")

    return JSONResponse(content=results)


@router.get("/events", tags=["Events"])
def get_events(client: str = None, last: int = 50):
    """Legge gli ultimi N eventi dal file NDJSON."""
    ndjson_path = EVENTS_DIR / "soc_events.ndjson"
    if not ndjson_path.exists():
        return {"events": [], "total": 0}

    events = []
    with open(ndjson_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if client and event.get("client") != client:
                    continue
                events.append(event)
            except json.JSONDecodeError:
                pass

    return {"events": events[-last:], "total": len(events)}

app.include_router(router)
