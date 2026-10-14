"""Request-ID middleware and a per-IP token-bucket rate limiter.

Design notes:

* Request IDs come from the ``X-Request-ID`` header when present, otherwise a
  fresh ``uuid4().hex``. They are bound to structlog context vars so every log
  line in the request scope carries them, and echoed in the response header.
* Rate limiting is per client IP and per process. Behind a proxy, the client IP
  comes from ``X-Forwarded-For`` (first hop). This is only safe if the proxy
  overwrites the header; we document that limitation and do not ship a
  trusted-proxy allowlist. Multi-worker deployments get per-worker buckets.
* ``/health`` is always allowed; the container healthcheck must never be
  rate-limited.
"""

import uuid
from dataclasses import dataclass, field

import structlog
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.services.clock import Clock

REQUEST_ID_HEADER = "X-Request-ID"
EXEMPT_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

log = structlog.get_logger("phishguard.middleware")


# --- request ID ------------------------------------------------------------------


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request ID to every request and bind it to structlog context."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


# --- rate limit ------------------------------------------------------------------


@dataclass
class _Bucket:
    """A single token bucket. Refills continuously; capacity is the burst size."""

    capacity: float
    refill_per_second: float
    tokens: float
    last_refill_mono: float

    @classmethod
    def full(cls, capacity: float, refill_per_second: float, now: float) -> "_Bucket":
        return cls(
            capacity=capacity,
            refill_per_second=refill_per_second,
            tokens=capacity,
            last_refill_mono=now,
        )

    def try_consume(self, now: float, cost: float = 1.0) -> bool:
        elapsed = max(0.0, now - self.last_refill_mono)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.last_refill_mono = now
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True

    def seconds_until(self, cost: float = 1.0) -> float:
        if self.tokens >= cost:
            return 0.0
        deficit = cost - self.tokens
        return deficit / self.refill_per_second


@dataclass
class RateLimiter:
    """In-process, per-key token bucket. Not shared across workers."""

    capacity: float
    refill_per_second: float
    clock: Clock
    buckets: dict[str, _Bucket] = field(default_factory=dict)

    def check(self, key: str) -> tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)``. ``retry_after`` is 0 if allowed."""
        now = self.clock.monotonic()
        bucket = self.buckets.get(key)
        if bucket is None:
            bucket = _Bucket.full(self.capacity, self.refill_per_second, now)
            self.buckets[key] = bucket
        if bucket.try_consume(now):
            return True, 0.0
        return False, bucket.seconds_until()


def _client_ip(request: Request) -> str:
    """Best-effort client IP. X-Forwarded-For is trusted as-is; see module docstring."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject over-limit requests with 429 and a structured body."""

    def __init__(self, app: ASGIApp, *, limiter: RateLimiter) -> None:
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.url.path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        allowed, retry_after = self._limiter.check(_client_ip(request))
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limited",
                    "detail": f"retry after {retry_after:.2f}s",
                },
                headers={"Retry-After": f"{max(1, int(retry_after + 0.999))}"},
            )
        return await call_next(request)


def install_middleware(app: FastAPI, *, limiter: RateLimiter) -> None:
    """Install request-ID then rate-limit middleware, in that order."""
    app.add_middleware(RateLimitMiddleware, limiter=limiter)
    app.add_middleware(RequestIdMiddleware)
