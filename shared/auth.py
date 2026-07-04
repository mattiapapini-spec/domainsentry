"""
Auth primitives — password hashing and token generation.
Pure stdlib (hashlib, hmac, secrets). No external dependencies.

Password storage: PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023),
random per-user salt, constant-time verification.

Tokens: opaque random (secrets), stored hashed (SHA-256) so a DB leak
does not expose usable session tokens.
"""

import hashlib
import hmac
import secrets

# OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password. Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify a password against stored hash. Constant-time comparison."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(dk.hex(), password_hash)


def generate_token() -> str:
    """Generate a high-entropy opaque session token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash a token for storage. Tokens are high-entropy so fast hash is fine."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── Role → permission presets ──
PERMISSIONS = [
    "manage_users",   # create/edit/disable users
    "assign_cases",   # assign cases to users
    "manage_cases",   # change case status, close
    "whitelist",      # trigger whitelist action
    "add_notes",      # add notes to cases
    "view",           # read cases
]

ROLE_PRESETS = {
    "admin":   ["manage_users", "assign_cases", "manage_cases", "whitelist", "add_notes", "view"],
    "analyst": ["assign_cases", "manage_cases", "whitelist", "add_notes", "view"],
    "viewer":  ["view"],
}


def permissions_for_role(role: str) -> list[str]:
    """Return the default permission set for a role."""
    return list(ROLE_PRESETS.get(role, ROLE_PRESETS["viewer"]))


def verify_token_remote(token: str, case_manager_url: str, session=None, timeout: int = 5):
    """
    Validate a bearer token against the case-manager (token introspection).

    Used by services other than the case-manager (e.g. feed-manager) that need
    to authenticate requests but don't own the user/session store. Returns the
    user dict {id, username, role, permissions} if the token is valid, else None.

    Follows the OAuth2 introspection pattern: the resource server (feed-manager)
    asks the auth server (case-manager) to validate the token. Works in both
    unified and multi-container deployments since it's a plain HTTP call.
    """
    import requests
    client = session or requests
    try:
        resp = client.get(
            f"{case_manager_url}/auth/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()
    except (requests.RequestException, ValueError):
        # ValueError covers a 200 with a non-JSON body (resp.json() failure).
        # Any failure → fail closed (treat as invalid).
        return None
    return None
