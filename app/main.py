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
from app.schemas import (
    EmailAggregate,
    EmailUrlVerdict,
    ErrorResponse,
    HealthResponse,
    PredictEmailRequest,
    PredictEmailResponse,
    PredictRequest,
    PredictResponse,
)
from app.services.clock import Clock, SystemClock
from app.services.email_extractor import extract_urls
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

    @app.post(
        "/predict_email",
        response_model=PredictEmailResponse,
        responses={
            422: {"model": ErrorResponse, "description": "invalid body"},
            429: {"model": ErrorResponse, "description": "rate limited"},
        },
    )
    async def predict_email(request: Request, body: PredictEmailRequest) -> PredictEmailResponse:
        predictor: Predictor = request.app.state.predictor
        settings: Settings = request.app.state.settings
        started = time.monotonic()

        urls, truncated = extract_urls(body.body, max_urls=settings.email_max_urls)

        results: list[EmailUrlVerdict] = []
        phishing_count = 0
        high_confidence_phishing = False
        for url in urls:
            try:
                verdict = await run_in_threadpool(predictor.predict, url)
            except Exception:  # one bad URL must not fail the whole scan
                continue
            results.append(
                EmailUrlVerdict(url=url, label=verdict.label, confidence=verdict.confidence)
            )
            if verdict.label == "phishing":
                phishing_count += 1
                if verdict.confidence >= 0.9:
                    high_confidence_phishing = True

        if phishing_count == 0:
            aggregate_verdict = "clean"
        elif high_confidence_phishing:
            aggregate_verdict = "phishing"
        else:
            aggregate_verdict = "suspicious"

        latency_ms = (time.monotonic() - started) * 1000.0
        log.info(
            "predict_email",
            endpoint="/predict_email",
            url_count=len(results),
            phishing_count=phishing_count,
            verdict=aggregate_verdict,
            truncated=truncated,
            latency_ms=round(latency_ms, 2),
        )

        return PredictEmailResponse(
            urls=results,
            aggregate=EmailAggregate(
                verdict=aggregate_verdict,
                phishing_count=phishing_count,
                total=len(results),
            ),
            truncated=truncated,
            model_version=predictor.model_version,
        )

    return app


app = create_app()


__all__ = ["PredictorError", "app", "create_app"]
