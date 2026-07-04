"""
Case Manager Service (:8012)
============================
SOC case management with structured auth.

- User management (admin creates users, assigns roles/permissions)
- Token-based authentication (opaque tokens, hashed at rest)
- Case lifecycle: new → in_progress → closed (TP/FP/benign)
- Assignment, notes, audit history
- Whitelist action (proxies to feed-manager) closes case as FP

Opt-in service: not required for the intelligence pipeline.
Enable it when you want case management inside DomainSentry instead
of an external SOAR.
"""

from typing import Optional, List
import os
import json
import sqlite3
import logging
import secrets
import hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import contextmanager

import requests
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from shared.compat import BaseModel, field_validator

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.auth import (hash_password, verify_password, generate_token,
                         hash_token, permissions_for_role, ROLE_PRESETS, PERMISSIONS)

logger = logging.getLogger("case-manager")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CASE] %(message)s")

app = FastAPI(title="Case Manager", version="4.1.0")
apply_security(app)
router = APIRouter()

DB_PATH = os.environ.get("CASES_DB", "/data/cases/cases.db")
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "12"))
FEED_URL = os.environ.get("FEED_URL", "http://feed-manager:8000")

# Optional service token for service-to-service calls (e.g. orchestrator case
# ingest). A non-expiring static secret mapped to a limited service identity.
# Set SERVICE_TOKEN to a long random value; leave empty to disable.
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")
SERVICE_PERMISSIONS = ["manage_cases", "view"]

VALID_STATUSES = ["new", "in_progress", "closed_tp", "closed_fp", "closed_benign"]
CLOSED_STATUSES = ["closed_tp", "closed_fp", "closed_benign"]


# ═══════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════

@contextmanager
def get_db():
    """Connection per operation. WAL mode + busy_timeout for concurrency."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create schema and bootstrap admin if no users exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                permissions TEXT NOT NULL DEFAULT '[]',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                client TEXT NOT NULL,
                classification TEXT,
                confidence TEXT,
                severity TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                assignee_id INTEGER,
                rationale TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(domain, client),
                FOREIGN KEY (assignee_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );
            CREATE TABLE IF NOT EXISTS case_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_client ON cases(client);
            CREATE INDEX IF NOT EXISTS idx_cases_assignee ON cases(assignee_id);
        """)

        # Bootstrap admin
        count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if count == 0:
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD")
            generated = False
            if not admin_pass:
                admin_pass = secrets.token_urlsafe(16)
                generated = True
            ph, salt = hash_password(admin_pass)
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, permissions, active, created_at, created_by) "
                "VALUES (?, ?, ?, 'admin', ?, 1, ?, 'bootstrap')",
                (admin_user, ph, salt, json.dumps(permissions_for_role("admin")), _now())
            )
            if generated:
                logger.warning("=" * 60)
                logger.warning(f"BOOTSTRAP ADMIN CREATED")
                logger.warning(f"  username: {admin_user}")
                logger.warning(f"  password: {admin_pass}")
                logger.warning(f"  CHANGE THIS PASSWORD IMMEDIATELY via /users/{{id}}/password")
                logger.warning("=" * 60)
            else:
                logger.info(f"Bootstrap admin '{admin_user}' created from ADMIN_PASSWORD env")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════
# AUTH DEPENDENCIES
# ═══════════════════════════════════════════════════════════════

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[7:]

    # Service token (service-to-service). Constant-time compare, non-expiring,
    # limited permissions. Only active when SERVICE_TOKEN is configured.
    if SERVICE_TOKEN and hmac.compare_digest(token, SERVICE_TOKEN):
        return {"id": None, "username": "svc-orchestrator",
                "role": "service", "permissions": list(SERVICE_PERMISSIONS)}

    token_h = hash_token(token)
    with get_db() as conn:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.username, u.role, u.permissions, u.active "
            "FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token_hash = ?",
            (token_h,)
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid token")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(401, "Token expired")
    if not row["active"]:
        raise HTTPException(403, "User account disabled")
    return {
        "id": row["user_id"], "username": row["username"],
        "role": row["role"], "permissions": json.loads(row["permissions"]),
    }


def require(permission: str):
    """Dependency factory: require a specific permission."""
    def checker(user=Depends(get_current_user)):
        if permission not in user["permissions"]:
            raise HTTPException(403, f"Permission required: {permission}")
        return user
    return checker


def _audit(conn, case_id: int, user_id, action: str, detail: str = ""):
    conn.execute(
        "INSERT INTO case_history (case_id, user_id, action, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
        (case_id, user_id, action, detail, _now())
    )


# ═══════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    try:
        with get_db() as conn:
            n = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        return {"status": "healthy", "service": "case-manager", "version": "4.1.0", "users": n}
    except Exception as e:
        return JSONResponse(status_code=503,
                            content={"status": "degraded", "error": sanitize_error(e)})


# ═══════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login", tags=["Auth"])
def login(req: LoginRequest):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, password_hash, salt, active FROM users WHERE username = ?",
            (req.username,)
        ).fetchone()
        # Constant-ish: always verify to reduce username enumeration timing
        if row:
            ok = verify_password(req.password, row["password_hash"], row["salt"])
        else:
            verify_password(req.password, "0" * 64, "0" * 32)
            ok = False
        if not row or not ok:
            raise HTTPException(401, "Invalid credentials")
        if not row["active"]:
            raise HTTPException(403, "User account disabled")

        token = generate_token()
        expires = (datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)).isoformat()
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (hash_token(token), row["id"], _now(), expires)
        )
    logger.info(f"Login: {sanitize_log_input(req.username)}")
    return {"token": token, "expires_at": expires, "token_type": "Bearer"}


@router.post("/auth/logout", tags=["Auth"])
def logout(authorization: str = Header(None), user=Depends(get_current_user)):
    token = authorization[7:]
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    return {"status": "logged_out"}


@router.get("/auth/me", tags=["Auth"])
def me(user=Depends(get_current_user)):
    return user


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT (admin only)
# ═══════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    permissions: Optional[List[str]] = None  # override; defaults from role

    @field_validator("username")
    @classmethod
    def valid_username(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]{2,64}$', v):
            raise ValueError("Username: 2-64 chars, alphanumeric/dot/dash/underscore")
        return v

    @field_validator("password")
    @classmethod
    def valid_password(cls, v):
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters")
        return v

    @field_validator("role")
    @classmethod
    def valid_role(cls, v):
        if v not in ROLE_PRESETS:
            raise ValueError(f"Role must be one of: {', '.join(ROLE_PRESETS)}")
        return v


@router.post("/users", tags=["Users"])
def create_user(req: UserCreate, admin=Depends(require("manage_users"))):
    perms = req.permissions if req.permissions is not None else permissions_for_role(req.role)
    invalid = set(perms) - set(PERMISSIONS)
    if invalid:
        raise HTTPException(400, f"Invalid permissions: {invalid}")
    ph, salt = hash_password(req.password)
    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, permissions, active, created_at, created_by) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (req.username, ph, salt, req.role, json.dumps(perms), _now(), admin["username"])
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"Username '{req.username}' already exists")
    logger.info(f"User created: {sanitize_log_input(req.username)} (role={req.role}) by {sanitize_log_input(admin['username'])}")
    return {"id": uid, "username": req.username, "role": req.role, "permissions": perms}


@router.get("/users/assignable", tags=["Users"])
def assignable_users(user=Depends(require("assign_cases"))):
    """
    Minimal list of active users (id + username only) for populating the
    assignment dropdown. Available to anyone who can assign cases — usernames
    are not sensitive, and this avoids requiring full manage_users (admin) just
    to assign a case to a colleague.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE active=1 ORDER BY username"
        ).fetchall()
    return {"users": [{"id": r["id"], "username": r["username"]} for r in rows]}


@router.get("/users", tags=["Users"])
def list_users(admin=Depends(require("manage_users"))):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, permissions, active, created_at, created_by FROM users ORDER BY id"
        ).fetchall()
    return {"users": [
        {"id": r["id"], "username": r["username"], "role": r["role"],
         "permissions": json.loads(r["permissions"]), "active": bool(r["active"]),
         "created_at": r["created_at"], "created_by": r["created_by"]}
        for r in rows
    ]}


class UserUpdate(BaseModel):
    role: Optional[str] = None
    permissions: Optional[List[str]] = None
    active: Optional[bool] = None


@router.patch("/users/{user_id}", tags=["Users"])
def update_user(user_id: int, req: UserUpdate, admin=Depends(require("manage_users"))):
    with get_db() as conn:
        row = conn.execute("SELECT id, username, role, permissions, active FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")

        role = req.role if req.role is not None else row["role"]
        if req.role is not None and req.role not in ROLE_PRESETS:
            raise HTTPException(400, f"Invalid role: {req.role}")

        if req.permissions is not None:
            invalid = set(req.permissions) - set(PERMISSIONS)
            if invalid:
                raise HTTPException(400, f"Invalid permissions: {invalid}")
            perms = req.permissions
        elif req.role is not None:
            perms = permissions_for_role(req.role)
        else:
            perms = json.loads(row["permissions"])

        active = row["active"] if req.active is None else (1 if req.active else 0)

        # Guard: don't let the last active admin be demoted/disabled
        if row["role"] == "admin" and (role != "admin" or active == 0):
            admin_count = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1 AND id != ?",
                (user_id,)
            ).fetchone()["n"]
            if admin_count == 0:
                raise HTTPException(400, "Cannot demote/disable the last active admin")

        conn.execute("UPDATE users SET role=?, permissions=?, active=? WHERE id=?",
                     (role, json.dumps(perms), active, user_id))
        # If disabled, revoke sessions
        if active == 0:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"id": user_id, "role": role, "permissions": perms, "active": bool(active)}


class PasswordReset(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def valid(cls, v):
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters")
        return v


@router.post("/users/{user_id}/password", tags=["Users"])
def reset_password(user_id: int, req: PasswordReset, user=Depends(get_current_user)):
    # Admin can reset anyone; users can reset their own
    if "manage_users" not in user["permissions"] and user["id"] != user_id:
        raise HTTPException(403, "Can only change your own password")
    ph, salt = hash_password(req.password)
    with get_db() as conn:
        r = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not r:
            raise HTTPException(404, "User not found")
        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (ph, salt, user_id))
        # Revoke existing sessions on password change
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"status": "password_changed", "id": user_id}


# ═══════════════════════════════════════════════════════════════
# CASES
# ═══════════════════════════════════════════════════════════════

class CaseIngest(BaseModel):
    domain: str
    client: str
    classification: Optional[str] = None
    confidence: Optional[str] = None
    severity: Optional[str] = None
    rationale: Optional[str] = None


@router.post("/cases/ingest", tags=["Cases"])
def ingest_case(req: CaseIngest, user=Depends(require("manage_cases"))):
    """
    Ingest an event into a case. Called by orchestrator/event-publisher or manually.
    - New domain → create case (status=new)
    - Open case → update classification
    - Closed case → reopen only if new severity is CRITICAL
    """
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id, status FROM cases WHERE domain=? AND client=?",
            (req.domain, req.client)
        ).fetchone()

        if not existing:
            cur = conn.execute(
                "INSERT INTO cases (domain, client, classification, confidence, severity, rationale, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?)",
                (req.domain, req.client, req.classification, req.confidence,
                 req.severity, req.rationale, _now(), _now())
            )
            cid = cur.lastrowid
            _audit(conn, cid, user["id"], "created", f"classification={req.classification}")
            return {"id": cid, "status": "new", "created": True}

        cid = existing["id"]
        if existing["status"] in CLOSED_STATUSES:
            if (req.severity or "").upper() == "CRITICAL":
                conn.execute("UPDATE cases SET status='new', classification=?, severity=?, rationale=?, updated_at=? WHERE id=?",
                             (req.classification, req.severity, req.rationale, _now(), cid))
                _audit(conn, cid, user["id"], "reopened", "auto-reopened: CRITICAL activity after closure")
                return {"id": cid, "status": "new", "reopened": True}
            return {"id": cid, "status": existing["status"], "updated": False}

        conn.execute("UPDATE cases SET classification=?, confidence=?, severity=?, rationale=?, updated_at=? WHERE id=?",
                     (req.classification, req.confidence, req.severity, req.rationale, _now(), cid))
        return {"id": cid, "status": existing["status"], "updated": True}


@router.get("/cases", tags=["Cases"])
def list_cases(status: str = None, client: str = None, assignee: int = None,
               severity: str = None, limit: int = 100, offset: int = 0,
               user=Depends(require("view"))):
    q = "SELECT c.*, u.username AS assignee_name FROM cases c LEFT JOIN users u ON c.assignee_id = u.id WHERE 1=1"
    params = []
    if status:
        q += " AND c.status = ?"; params.append(status)
    if client:
        q += " AND c.client = ?"; params.append(client)
    if assignee is not None:
        q += " AND c.assignee_id = ?"; params.append(assignee)
    if severity:
        q += " AND c.severity = ?"; params.append(severity)
    q += " ORDER BY c.updated_at DESC LIMIT ? OFFSET ?"
    params.extend([min(limit, 500), offset])
    with get_db() as conn:
        rows = conn.execute(q, params).fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
    return {"cases": [dict(r) for r in rows], "count": len(rows), "total": total}


@router.get("/cases/{case_id}", tags=["Cases"])
def get_case(case_id: int, user=Depends(require("view"))):
    with get_db() as conn:
        case = conn.execute(
            "SELECT c.*, u.username AS assignee_name FROM cases c LEFT JOIN users u ON c.assignee_id=u.id WHERE c.id=?",
            (case_id,)
        ).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        notes = conn.execute(
            "SELECT n.note, n.created_at, u.username FROM case_notes n JOIN users u ON n.user_id=u.id "
            "WHERE n.case_id=? ORDER BY n.created_at", (case_id,)
        ).fetchall()
        history = conn.execute(
            "SELECT h.action, h.detail, h.timestamp, u.username FROM case_history h "
            "LEFT JOIN users u ON h.user_id=u.id WHERE h.case_id=? ORDER BY h.timestamp", (case_id,)
        ).fetchall()
    return {"case": dict(case), "notes": [dict(n) for n in notes], "history": [dict(h) for h in history]}


class StatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def valid(cls, v):
        if v not in VALID_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(VALID_STATUSES)}")
        return v


@router.patch("/cases/{case_id}/status", tags=["Cases"])
def update_status(case_id: int, req: StatusUpdate, user=Depends(require("manage_cases"))):
    with get_db() as conn:
        row = conn.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Case not found")
        conn.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?", (req.status, _now(), case_id))
        _audit(conn, case_id, user["id"], "status_changed", f"{row['status']} → {req.status}")
    return {"id": case_id, "status": req.status}


class AssignRequest(BaseModel):
    assignee_id: Optional[int]  # None to unassign


@router.post("/cases/{case_id}/assign", tags=["Cases"])
def assign_case(case_id: int, req: AssignRequest, user=Depends(require("assign_cases"))):
    with get_db() as conn:
        row = conn.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Case not found")
        assignee_name = None
        if req.assignee_id is not None:
            a = conn.execute("SELECT username FROM users WHERE id=? AND active=1", (req.assignee_id,)).fetchone()
            if not a:
                raise HTTPException(404, "Assignee not found or disabled")
            assignee_name = a["username"]
        new_status = "in_progress" if req.assignee_id is not None else "new"
        conn.execute("UPDATE cases SET assignee_id=?, status=CASE WHEN status='new' THEN ? ELSE status END, updated_at=? WHERE id=?",
                     (req.assignee_id, new_status, _now(), case_id))
        _audit(conn, case_id, user["id"], "assigned",
               f"assigned to {assignee_name}" if assignee_name else "unassigned")
    return {"id": case_id, "assignee_id": req.assignee_id, "assignee_name": assignee_name}


class NoteRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def valid(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Note cannot be empty")
        if len(v) > 5000:
            raise ValueError("Note too long (max 5000 chars)")
        return v


@router.post("/cases/{case_id}/notes", tags=["Cases"])
def add_note(case_id: int, req: NoteRequest, user=Depends(require("add_notes"))):
    with get_db() as conn:
        row = conn.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Case not found")
        conn.execute("INSERT INTO case_notes (case_id, user_id, note, created_at) VALUES (?, ?, ?, ?)",
                     (case_id, user["id"], req.note, _now()))
        conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (_now(), case_id))
    return {"status": "note_added", "case_id": case_id}


class WhitelistRequest(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def valid(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Reason cannot be empty")
        return v


@router.post("/cases/{case_id}/whitelist", tags=["Cases"])
def whitelist_case(case_id: int, req: WhitelistRequest,
                   authorization: str = Header(None),
                   user=Depends(require("whitelist"))):
    """
    Whitelist the case's domain (proxies to feed-manager) and close as FP.
    Resolves the false-positive problem: verify once, never re-triage.
    """
    with get_db() as conn:
        case = conn.execute("SELECT domain, client FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")

    # Proxy to feed-manager. Forward the caller's token so the call passes
    # feed-manager auth when FEED_REQUIRE_AUTH is enabled (same user holds the
    # 'whitelist' permission that the feed-manager will also check).
    headers = {"Authorization": authorization} if authorization else {}
    try:
        resp = requests.post(
            f"{FEED_URL}/feed/whitelist?client={case['client']}",
            json={"domain": case["domain"], "reason": req.reason, "added_by": user["username"]},
            headers=headers,
            timeout=10
        )
        if not resp.ok:
            raise HTTPException(502, f"feed-manager rejected whitelist: HTTP {resp.status_code}")
    except requests.RequestException as e:
        raise HTTPException(502, f"feed-manager unreachable: {sanitize_error(e)}")

    with get_db() as conn:
        conn.execute("UPDATE cases SET status='closed_fp', updated_at=? WHERE id=?", (_now(), case_id))
        _audit(conn, case_id, user["id"], "whitelisted", f"{case['domain']}: {req.reason}")
        conn.execute("INSERT INTO case_notes (case_id, user_id, note, created_at) VALUES (?, ?, ?, ?)",
                     (case_id, user["id"], f"Whitelisted and closed as FP: {req.reason}", _now()))
    logger.info(f"Whitelisted {sanitize_log_input(case['domain'])} by {sanitize_log_input(user['username'])}")
    return {"id": case_id, "domain": case["domain"], "status": "closed_fp", "whitelisted": True}


# ═══════════════════════════════════════════════════════════════
# DASHBOARD SUMMARY (for triage view)
# ═══════════════════════════════════════════════════════════════

@router.get("/summary", tags=["Cases"])
def summary(user=Depends(require("view"))):
    """Triage summary: counts by status, severity, recent activity."""
    with get_db() as conn:
        by_status = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM cases GROUP BY status").fetchall()}
        by_severity = {r["severity"] or "unknown": r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM cases WHERE status NOT IN ('closed_tp','closed_fp','closed_benign') GROUP BY severity").fetchall()}
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE updated_at > ?", (cutoff,)).fetchone()["n"]
        open_unassigned = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE status='new' AND assignee_id IS NULL").fetchone()["n"]
        # Open cases per client (for the Clients view)
        by_client = {r["client"]: r["n"] for r in conn.execute(
            "SELECT client, COUNT(*) AS n FROM cases WHERE status NOT IN ('closed_tp','closed_fp','closed_benign') GROUP BY client").fetchall()}
    return {
        "by_status": by_status,
        "open_by_severity": by_severity,
        "by_client": by_client,
        "updated_last_24h": recent,
        "new_unassigned": open_unassigned,
    }


# Initialize DB on import
init_db()

app.include_router(router)
