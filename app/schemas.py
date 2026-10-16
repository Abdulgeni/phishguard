"""Pydantic request/response models for the PhishGuard API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Labels emitted by the model, mapped from the {0,1} training target.
Label = Literal["phishing", "benign"]


class PredictRequest(BaseModel):
    """A single URL to classify."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048, description="URL to classify")


class PredictResponse(BaseModel):
    """Classification result for a single URL."""

    label: Label
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str
    features: dict[str, int]
    explanation: dict[str, object] | None = None


class HealthResponse(BaseModel):
    """Liveness + readiness combined."""

    status: Literal["ok"]
    model_version: str
    model_loaded: bool


AggregateVerdict = Literal["phishing", "suspicious", "clean"]


class PredictEmailRequest(BaseModel):
    """A raw email body to scan for phishing URLs."""

    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=102_400, description="raw email body")


class EmailUrlVerdict(BaseModel):
    """Per-URL result inside an email scan."""

    url: str
    label: Label
    confidence: float = Field(ge=0.0, le=1.0)


class EmailAggregate(BaseModel):
    """Aggregate verdict across all URLs in an email."""

    verdict: AggregateVerdict
    phishing_count: int = Field(ge=0)
    total: int = Field(ge=0)


class PredictEmailResponse(BaseModel):
    """Full email scan result."""

    urls: list[EmailUrlVerdict]
    aggregate: EmailAggregate
    truncated: bool
    model_version: str


class ErrorResponse(BaseModel):
    """Structured error payload for 4xx/5xx responses from our handlers."""

    error: str
    detail: str
