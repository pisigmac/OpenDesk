"""Request context middleware and security headers."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_request_ctx: ContextVar[dict] = ContextVar("request_ctx", default={})

# Security headers added to every response
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'",
}


def get_request_context() -> dict:
    return _request_ctx.get()


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        token = _request_ctx.set({"request_id": request_id, "ip": ip, "user_agent": user_agent})
        try:
            response = await call_next(request)
        finally:
            _request_ctx.reset(token)
        response.headers["x-request-id"] = request_id
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response
