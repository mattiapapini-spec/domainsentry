"""
Security middleware — headers, error sanitization, request limits.
Applied to both unified and individual service apps.
"""

import re
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger("security")

# Max request body: 1MB
MAX_BODY_SIZE = 1 * 1024 * 1024


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        # Remove server header to avoid version disclosure
        if "server" in response.headers:
            del response.headers["server"]
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests with body exceeding MAX_BODY_SIZE."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "max_bytes": MAX_BODY_SIZE}
            )
        return await call_next(request)


def sanitize_error(error: Exception) -> str:
    """
    Sanitize error messages for API responses.
    Removes internal paths, stack traces, and sensitive info.
    """
    msg = str(error)
    # Remove filesystem paths
    msg = re.sub(r'/[\w/.-]+\.py', '[internal]', msg)
    msg = re.sub(r'/home/\S+', '[internal]', msg)
    msg = re.sub(r'/app/\S+', '[internal]', msg)
    msg = re.sub(r'/data/\S+', '[path]', msg)
    msg = re.sub(r'/tmp/\S+', '[path]', msg)
    # Remove line numbers
    msg = re.sub(r', line \d+', '', msg)
    # Truncate
    if len(msg) > 200:
        msg = msg[:200] + "..."
    return msg


def sanitize_log_input(value: str) -> str:
    """
    Sanitize user input before logging.
    Prevents log injection via newlines, ANSI escape codes, control chars.
    """
    if not isinstance(value, str):
        return str(value)
    # Remove ANSI escape sequences
    value = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', value)
    # Remove control characters (except space)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # Replace newlines/tabs with spaces
    value = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Truncate
    if len(value) > 253:
        value = value[:253]
    return value


def apply_security(app):
    """Apply all security middleware to a FastAPI app."""
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    return app
