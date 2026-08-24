"""Simple in-memory rate limiter for Auth endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Lock

from fastapi import HTTPException, Request, status

from opendesk_auth.config import Settings, get_settings


def _client_ip(request: Request) -> str:
    """Return the client identifier for rate limiting.

    When behind a trusted reverse proxy, the first IP in the configured proxy
    header is used. Otherwise the direct transport client address is used.
    """
    settings = get_settings()
    if settings.rate_limit_trust_proxy:
        header_value = request.headers.get(settings.rate_limit_proxy_header.lower())
        if header_value:
            # X-Forwarded-For: client, proxy1, proxy2, ...
            return header_value.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


class RateLimiter:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._store: dict[str, list[datetime]] = {}
        self._lock = Lock()

    def _limit(self, action: str) -> int:
        return getattr(self.settings, f"rate_limit_{action}", 10)

    def _window(self, action: str) -> int:
        return getattr(self.settings, f"rate_limit_{action}_window_seconds", 60)

    def is_allowed(self, identifier: str, action: str) -> bool:
        key = f"{action}:{identifier}"
        limit = self._limit(action)
        window_seconds = self._window(action)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            timestamps = [t for t in self._store.get(key, []) if t > cutoff]
            if len(timestamps) >= limit:
                self._store[key] = timestamps
                return False
            timestamps.append(now)
            self._store[key] = timestamps
            return True


def rate_limit_dependency(action: str):
    """Returns a FastAPI dependency that enforces rate limits by client IP."""

    def _limit(request: Request) -> None:
        identifier = _client_ip(request)
        limiter: RateLimiter = request.app.state.rate_limiter
        if not limiter.is_allowed(identifier, action):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
            )

    return _limit
