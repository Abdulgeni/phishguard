from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings

ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


def test_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.app_env == "dev"
    assert s.max_url_length == 2048
    assert s.request_budget_seconds == 3.0
    assert s.whois_timeout_seconds == 2.0
    assert s.dataset_path is None
    assert s.min_f1 == 0.90


def test_env_overrides_and_log_level_is_uppercased(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHOIS_DISABLED", "true")
    monkeypatch.setenv("REQUEST_BUDGET_SECONDS", "1.5")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    s = Settings(_env_file=None)
    assert s.whois_disabled is True
    assert s.request_budget_seconds == 1.5
    assert s.log_level == "DEBUG"


def test_blank_dataset_path_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATASET_PATH", "")
    assert Settings(_env_file=None).dataset_path is None


@pytest.mark.parametrize(
    ("name", "value"),
    [("REQUEST_BUDGET_SECONDS", "0"), ("APP_ENV", "staging"), ("MIN_F1", "1.5")],
)
def test_invalid_values_fail_loudly(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_fake_delay_only_effective_in_test_env() -> None:
    effective_in_test = Settings(
        _env_file=None, app_env="test", whois_fake_delay_seconds=5
    ).whois_fake_delay_effective
    effective_in_dev = Settings(
        _env_file=None, app_env="dev", whois_fake_delay_seconds=5
    ).whois_fake_delay_effective
    assert effective_in_test == 5.0
    assert effective_in_dev == 0.0


def test_env_example_parses_cleanly() -> None:
    s = Settings(_env_file=ENV_EXAMPLE)
    assert s.app_env == "dev"
    assert s.log_level == "INFO"
    assert s.email_request_budget_seconds == 10.0
    assert s.dataset_path is None
    assert s.eval_dataset_path is None


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)  # no stray .env
    assert get_settings() is get_settings()
