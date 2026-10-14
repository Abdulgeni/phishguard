"""Structured error handling for the API.

Pydantic's default 422 payload is verbose and not shaped like our ``ErrorResponse``.
We remap it here so every 4xx/5xx the API emits looks the same.
"""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.features.normalize import InvalidUrlError


def _payload(error: str, detail: str) -> dict[str, str]:
    return {"error": error, "detail": detail}


def install_error_handlers(app: FastAPI) -> None:
    """Wire our structured error handlers onto ``app``."""

    @app.exception_handler(InvalidUrlError)
    async def _invalid_url(_request: Request, exc: InvalidUrlError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_payload(f"invalid_url:{exc.reason}", exc.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", ()))
        detail = str(first.get("msg", "request validation failed"))
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_payload("validation_error", f"{location}: {detail}".strip(": ")),
        )
