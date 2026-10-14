"""FastAPI application: /health, /predict, /docs, /openapi.json."""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.errors import install_error_handlers
from app.features.host import HostFeatureExtractor
from app.schemas import ErrorResponse, HealthResponse, PredictRequest, PredictResponse
from app.services.clock import Clock, SystemClock
from app.services.predictor import Predictor, PredictorError

log = structlog.get_logger("phishguard.api")


def _build_predictor(settings: Settings, clock: Clock) -> Predictor:
    host = HostFeatureExtractor.from_settings(settings, clock)
    return Predictor(
        model_path=settings.model_path,
        clock=clock,
        host_extractor=host,
        request_budget_seconds=settings.request_budget_seconds,
        enable_explanations=settings.enable_explanations,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    clock = SystemClock()
    predictor = _build_predictor(settings, clock)
    app.state.settings = settings
    app.state.clock = clock
    app.state.predictor = predictor
    log.info(
        "startup",
        model_version=predictor.model_version,
        model_path=str(settings.model_path),
        app_env=settings.app_env,
    )
    yield
    log.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="PhishGuard",
        version="0.1.0",
        description="Phishing URL classifier: lexical + host features, tree ensemble.",
        lifespan=lifespan,
    )
    install_error_handlers(app)

    @app.get("/health", response_model=HealthResponse)
    async def health(request: Request) -> HealthResponse | JSONResponse:
        predictor: Predictor | None = getattr(request.app.state, "predictor", None)
        if predictor is None:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )
        return HealthResponse(
            status="ok",
            model_version=predictor.model_version,
            model_loaded=True,
        )

    @app.post(
        "/predict",
        response_model=PredictResponse,
        responses={
            422: {"model": ErrorResponse, "description": "invalid URL"},
            500: {"model": ErrorResponse, "description": "internal error"},
        },
    )
    async def predict(request: Request, body: PredictRequest) -> PredictResponse:
        predictor: Predictor = request.app.state.predictor
        started = time.monotonic()
        verdict = await run_in_threadpool(predictor.predict, body.url)
        latency_ms = (time.monotonic() - started) * 1000.0
        log.info(
            "predict",
            endpoint="/predict",
            label=verdict.label,
            confidence=round(verdict.confidence, 4),
            latency_ms=round(latency_ms, 2),
            whois_skipped=verdict.features.get("domain_age_days", -1) == -1,
        )
        return PredictResponse(
            label=verdict.label,
            confidence=verdict.confidence,
            model_version=verdict.model_version,
            features=verdict.features,
            explanation=verdict.explanation,
        )

    return app


app = create_app()


__all__ = ["PredictorError", "app", "create_app"]
