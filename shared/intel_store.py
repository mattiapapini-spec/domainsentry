"""
Intelligence store
===================
Persists per-domain intelligence for the dashboard's Intelligence tab.

Two artifacts per domain, both on disk under INTEL_DIR:
  - snapshot:  intel_snapshots/{client}/{domain}.json   (overwritten each scan)
       the full current intel: dns, cert, http, whois, reputation
  - history:   intel_history/{client}/{domain}.ndjson    (appended, deltas only)
       one line per scan that produced changes: timestamp + baseline diff alerts

Design: the snapshot does not grow (overwrite); the history grows slowly
(only when something changes), keeping storage bounded.
"""

import os
import json
import re
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("intel-store")

INTEL_DIR = Path(os.environ.get("INTEL_DIR", "/data/intel"))
SNAP_DIR = INTEL_DIR / "snapshots"
HIST_DIR = INTEL_DIR / "history"

_SAFE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _safe(name: str) -> str:
    """Reject path traversal in client/domain names used as file paths."""
    name = (name or "").strip().lower()
    if not name or not _SAFE.match(name) or ".." in name or set(name) == {"."}:
        raise ValueError(f"unsafe name: {name!r}")
    return name


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_snapshot(client: str, domain: str) -> dict | None:
    """Return the previous full intel snapshot for a domain, or None."""
    try:
        p = SNAP_DIR / _safe(client) / f"{_safe(domain)}.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError) as e:
        logger.warning(f"load_snapshot {client}/{domain}: {e}")
    return None


def save_snapshot(client: str, domain: str, intel: dict) -> bool:
    """Overwrite the current full intel snapshot for a domain."""
    try:
        d = SNAP_DIR / _safe(client)
        d.mkdir(parents=True, exist_ok=True)
        record = {"domain": domain, "client": client, "updated_at": _now(), "intel": intel}
        tmp = d / f"{_safe(domain)}.json.tmp"
        final = d / f"{_safe(domain)}.json"
        tmp.write_text(json.dumps(record), encoding="utf-8")
        tmp.replace(final)  # atomic
        return True
    except (ValueError, OSError) as e:
        logger.warning(f"save_snapshot {client}/{domain}: {e}")
        return False


def append_history(client: str, domain: str, diff: dict) -> bool:
    """
    Append a diff entry to the domain's history — only the deltas, not a full
    snapshot. Skips writing if the diff has no alerts (nothing changed).
    """
    alerts = diff.get("alerts", [])
    if not alerts:
        return False  # nothing changed, don't grow the history
    try:
        d = HIST_DIR / _safe(client)
        d.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": _now(),
            "max_severity": diff.get("max_severity", "CLEAN"),
            "alert_count": diff.get("alert_count", len(alerts)),
            "alerts": alerts,
        }
        with open(d / f"{_safe(domain)}.ndjson", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return True
    except (ValueError, OSError) as e:
        logger.warning(f"append_history {client}/{domain}: {e}")
        return False


def load_history(client: str, domain: str, limit: int = 100) -> list:
    """Return the diff history for a domain, most recent first."""
    try:
        p = HIST_DIR / _safe(client) / f"{_safe(domain)}.ndjson"
        if not p.exists():
            return []
        lines = p.read_text(encoding="utf-8").strip().split("\n")
        entries = [json.loads(ln) for ln in lines if ln.strip()]
        return list(reversed(entries))[:limit]
    except (ValueError, OSError, json.JSONDecodeError) as e:
        logger.warning(f"load_history {client}/{domain}: {e}")
        return []


def get_intel(client: str, domain: str) -> dict:
    """Combined view: current snapshot + diff history for a domain."""
    snap = load_snapshot(client, domain)
    return {
        "domain": domain,
        "client": client,
        "snapshot": snap,
        "history": load_history(client, domain),
        "available": snap is not None,
    }
