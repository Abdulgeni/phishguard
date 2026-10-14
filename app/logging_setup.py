"""Structured JSON-lines logging on stdout (structlog + stdlib bridge)."""

import logging
import sys

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from app.config import Settings
from app.services.clock import Clock


def _timestamper(clock: Clock) -> Processor:
    def add_ts(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
        event_dict["ts"] = clock.now().isoformat(timespec="milliseconds")
        return event_dict

    return add_ts


def configure_logging(level: str, clock: Clock) -> None:
    """Route structlog AND stdlib logging through one JSON formatter. Idempotent."""
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        _timestamper(clock),
        structlog.processors.format_exc_info,
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def log_startup(settings: Settings) -> None:
    """One line proving which configuration the process actually loaded."""
    log = structlog.get_logger("phishguard")
    log.info(
        "startup",
        settings=settings.model_dump(mode="json"),
        whois_fake_delay_effective=settings.whois_fake_delay_effective,
    )
    if settings.whois_fake_delay_seconds > 0 and settings.whois_fake_delay_effective == 0:
        log.warning(
            "whois_fake_delay_ignored",
            app_env=settings.app_env,
            configured=settings.whois_fake_delay_seconds,
        )
