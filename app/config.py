"""Typed application settings, loaded from the environment (and optional .env)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["dev", "test", "prod"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: AppEnv = "dev"
    log_level: LogLevel = "INFO"

    # Model
    model_path: Path = Path("artifacts/model.joblib")
    enable_explanations: bool = False

    # Request limits and budget
    max_url_length: int = Field(2048, gt=0)
    request_budget_seconds: float = Field(3.0, gt=0)
    email_request_budget_seconds: float = Field(10.0, gt=0)
    email_max_body_bytes: int = Field(102_400, gt=0)
    email_max_urls: int = Field(20, gt=0)

    # WHOIS
    whois_disabled: bool = False
    whois_timeout_seconds: float = Field(2.0, gt=0)
    whois_fake_delay_seconds: float = Field(0.0, ge=0)

    # Training / evaluation (None = unset; scripts must fail loudly)
    dataset_path: Path | None = None
    eval_dataset_path: Path | None = None
    min_f1: float = Field(0.90, ge=0, le=1)

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("dataset_path", "eval_dataset_path", mode="before")
    @classmethod
    def _blank_path_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def whois_fake_delay_effective(self) -> float:
        """The fake WHOIS delay is a test hook: honored only when APP_ENV=test."""
        return self.whois_fake_delay_seconds if self.app_env == "test" else 0.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
