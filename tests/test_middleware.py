"""Unit tests for app.middleware: request ID + rate limiter."""

from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware import (
    EXEMPT_PATHS,
    REQUEST_ID_HEADER,
    RateLimiter,
    _Bucket,
    install_middleware,
)
from app.services.clock import FakeClock

START = datetime(2026, 1, 1, tzinfo=UTC)


def _app_with(limiter: RateLimiter) -> FastAPI:
    app = FastAPI()
    install_middleware(app, limiter=limiter)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/predict")
    def predict() -> dict[str, str]:
        return {"label": "benign"}

    return app


def test_request_id_is_generated_when_absent() -> None:
    limiter = RateLimiter(capacity=100, refill_per_second=100, clock=FakeClock(START))
    client = TestClient(_app_with(limiter))
    r = client.get("/health")
    assert r.status_code == 200
    assert REQUEST_ID_HEADER in r.headers
    assert len(r.headers[REQUEST_ID_HEADER]) == 32  # uuid4().hex


def test_request_id_is_echoed_from_header() -> None:
    limiter = RateLimiter(capacity=100, refill_per_second=100, clock=FakeClock(START))
    client = TestClient(_app_with(limiter))
    r = client.get("/health", headers={REQUEST_ID_HEADER: "abc-123"})
    assert r.headers[REQUEST_ID_HEADER] == "abc-123"


def test_health_is_exempt_from_rate_limit() -> None:
    limiter = RateLimiter(capacity=1, refill_per_second=0.0001, clock=FakeClock(START))
    client = TestClient(_app_with(limiter))
    for _ in range(10):
        r = client.get("/health")
        assert r.status_code == 200


def test_predict_is_rate_limited() -> None:
    limiter = RateLimiter(capacity=2, refill_per_second=0.0001, clock=FakeClock(START))
    client = TestClient(_app_with(limiter))
    assert client.post("/predict").status_code == 200
    assert client.post("/predict").status_code == 200
    r = client.post("/predict")
    assert r.status_code == 429
    body = r.json()
    assert body["error"] == "rate_limited"
    assert "retry after" in body["detail"]
    assert "Retry-After" in r.headers


def test_rate_limit_recovers_after_refill() -> None:
    clock = FakeClock(START)
    limiter = RateLimiter(capacity=1, refill_per_second=1.0, clock=clock)
    client = TestClient(_app_with(limiter))
    assert client.post("/predict").status_code == 200
    assert client.post("/predict").status_code == 429
    clock.advance(1.5)  # refill one token
    assert client.post("/predict").status_code == 200


def test_rate_limit_keys_by_client_ip() -> None:
    limiter = RateLimiter(capacity=1, refill_per_second=0.0001, clock=FakeClock(START))
    client = TestClient(_app_with(limiter))
    assert client.post("/predict", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.post("/predict", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200
    assert client.post("/predict", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429


def test_bucket_consumes_and_refills() -> None:
    b = _Bucket.full(capacity=3, refill_per_second=1.0, now=0.0)
    assert b.try_consume(0.0) is True
    assert b.try_consume(0.0) is True
    assert b.try_consume(0.0) is True
    assert b.try_consume(0.0) is False
    assert b.try_consume(1.0) is True
    assert b.try_consume(1.0) is False


def test_exempt_paths_are_documented() -> None:
    assert "/health" in EXEMPT_PATHS
    assert "/docs" in EXEMPT_PATHS
    assert "/openapi.json" in EXEMPT_PATHS
