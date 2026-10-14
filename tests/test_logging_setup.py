import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import structlog

from app.__main__ import main
from app.config import Settings
from app.logging_setup import configure_logging, log_startup
from app.services.clock import FakeClock


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    logging.getLogger().handlers.clear()
    structlog.reset_defaults()
    structlog.contextvars.clear_contextvars()


def _lines(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_structlog_emits_json_with_clock_timestamp(capsys: pytest.CaptureFixture[str]) -> None:
    clock = FakeClock(datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC))
    configure_logging("INFO", clock)
    log = structlog.get_logger("t")
    log.info("hello", a=1)
    clock.advance(1.5)
    log.info("later")
    first, second = _lines(capsys)
    assert first["event"] == "hello"
    assert first["a"] == 1
    assert first["level"] == "info"
    assert first["ts"] == "2026-03-04T05:06:07.000+00:00"
    assert second["ts"] == "2026-03-04T05:06:08.500+00:00"


def test_stdlib_logs_are_json_too(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", FakeClock())
    logging.getLogger("third.party").warning("careful %s", "now")
    [line] = _lines(capsys)
    assert line["event"] == "careful now"
    assert line["level"] == "warning"
    assert "ts" in line


def test_level_filtering(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("WARNING", FakeClock())
    structlog.get_logger("t").info("hidden")
    structlog.get_logger("t").warning("shown")
    assert [line["event"] for line in _lines(capsys)] == ["shown"]


def test_contextvars_are_merged(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", FakeClock())
    structlog.contextvars.bind_contextvars(request_id="abc")
    structlog.get_logger("t").info("with_ctx")
    [line] = _lines(capsys)
    assert line["request_id"] == "abc"


def test_startup_line_reflects_settings(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", FakeClock())
    log_startup(Settings(_env_file=None, whois_disabled=True, request_budget_seconds=1.5))
    [line] = _lines(capsys)
    assert line["event"] == "startup"
    assert line["settings"]["whois_disabled"] is True
    assert line["settings"]["request_budget_seconds"] == 1.5
    assert isinstance(line["settings"]["model_path"], str)


def test_ignored_fake_delay_warns_outside_test_env(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", FakeClock())
    log_startup(Settings(_env_file=None, app_env="dev", whois_fake_delay_seconds=3.0))
    events = _lines(capsys)
    assert [e["event"] for e in events] == ["startup", "whois_fake_delay_ignored"]
    assert events[1]["level"] == "warning"


def test_no_warning_when_fake_delay_is_effective(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", FakeClock())
    log_startup(Settings(_env_file=None, app_env="test", whois_fake_delay_seconds=3.0))
    [line] = _lines(capsys)
    assert line["whois_fake_delay_effective"] == 3.0


def test_main_loads_environment(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("LOG_LEVEL", "debug")
    monkeypatch.setenv("WHOIS_DISABLED", "true")
    main()
    [line] = _lines(capsys)
    assert line["event"] == "startup"
    assert line["settings"]["log_level"] == "DEBUG"
    assert line["settings"]["whois_disabled"] is True
