import socket
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
import whois
from structlog.testing import capture_logs

from app.config import Settings
from app.features.host import (
    HOST_FEATURE_NAMES,
    HostFeatureExtractor,
    HostResult,
    WhoisRecord,
    is_shortener,
    load_shorteners,
    parse_whois_response,
    python_whois_lookup,
    registered_domain,
)
from app.features.normalize import normalize_url
from app.services.clock import FakeClock

START = datetime(2026, 1, 1, tzinfo=UTC)
CREATED = datetime(2020, 1, 1, tzinfo=UTC)  # exactly 2192 days before START
RECORD = WhoisRecord(creation_date=CREATED, registrar="Acme Registrar")
SENTINELS = {"domain_age_days": -1, "is_shortener": 0, "registrar_known": 0}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", blocked)


@pytest.fixture
def gate() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()  # never leave a lookup thread blocked


class Recorder:
    """Fake WHOIS lookup: records calls, optionally blocks on a gate or raises."""

    def __init__(
        self,
        record: WhoisRecord = RECORD,
        error: Exception | None = None,
        gate: threading.Event | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.record = record
        self.error = error
        self.gate = gate

    def __call__(self, domain: str) -> WhoisRecord:
        self.calls.append(domain)
        if self.gate is not None:
            self.gate.wait(10)
        if self.error is not None:
            raise self.error
        return self.record


def make(lookup: Recorder, clock: FakeClock | None = None, **kwargs: Any) -> HostFeatureExtractor:
    return HostFeatureExtractor(clock=clock or FakeClock(START), lookup=lookup, **kwargs)


def run(ex: HostFeatureExtractor, raw: str, **kwargs: Any) -> HostResult:
    return ex.extract(normalize_url(raw), **kwargs)


def wait_for(predicate: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met in time")


def failures(logs: list[dict[str, Any]]) -> list[str]:
    return [e["reason"] for e in logs if e["event"] == "whois_failed"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("bit.ly", True),
        ("www.bit.ly", True),
        ("t.co", True),
        ("BIT.LY", True),
        ("notbit.ly", False),
        ("bit.ly.evil.com", False),
        ("example.com", False),
        ("ly", False),
    ],
)
def test_is_shortener(host: str, expected: bool) -> None:
    assert is_shortener(host) is expected


def test_shortener_list_hygiene() -> None:
    domains = load_shorteners()
    assert len(domains) >= 20
    assert {"bit.ly", "t.co", "tinyurl.com"} <= domains
    for d in domains:
        assert d == d.lower().strip()
        assert "." in d
        assert "/" not in d
        assert ":" not in d


def test_parse_takes_earliest_date_and_first_nonempty_registrar() -> None:
    data = {
        "creation_date": [datetime(2021, 5, 1), datetime(2019, 1, 2, tzinfo=UTC)],
        "registrar": ["", "  Acme  "],
    }
    rec = parse_whois_response(data)
    assert rec.creation_date == datetime(2019, 1, 2, tzinfo=UTC)
    assert rec.registrar == "Acme"


def test_parse_handles_naive_str_and_date_values() -> None:
    assert parse_whois_response({"creation_date": datetime(2020, 3, 4, 5, 6)}).creation_date == (
        datetime(2020, 3, 4, 5, 6, tzinfo=UTC)
    )
    assert parse_whois_response({"creation_date": "2020-03-04"}).creation_date == (
        datetime(2020, 3, 4, tzinfo=UTC)
    )
    assert parse_whois_response({"creation_date": date(2020, 3, 4)}).creation_date == (
        datetime(2020, 3, 4, tzinfo=UTC)
    )


@pytest.mark.parametrize("value", [None, "not a date", 12345, [], [None, "x"]])
def test_parse_garbage_dates_become_none(value: object) -> None:
    assert parse_whois_response({"creation_date": value}).creation_date is None


@pytest.mark.parametrize("value", [None, "", "   ", 123, [], [None, ""]])
def test_parse_garbage_registrars_become_none(value: object) -> None:
    assert parse_whois_response({"registrar": value}).registrar is None


def test_python_whois_lookup_wraps_the_library(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_whois(domain: str) -> dict[str, Any]:
        seen.append(domain)
        return {"creation_date": [datetime(2020, 1, 1), datetime(2019, 6, 1)], "registrar": "R"}

    monkeypatch.setattr(whois, "whois", fake_whois)
    rec = python_whois_lookup("example.com")
    assert seen == ["example.com"]
    assert rec == WhoisRecord(datetime(2019, 6, 1, tzinfo=UTC), "R")


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("EXAMPLE.COM", "example.com"),
        ("xn--bcher-kva.example.com", "example.com"),
        ("localhost", None),
    ],
)
def test_registered_domain(host: str, expected: str | None) -> None:
    assert registered_domain(host) == expected


def test_success_contract_and_order() -> None:
    rec = Recorder()
    result = run(make(rec), "https://www.example.com/a")
    assert tuple(result.features) == HOST_FEATURE_NAMES
    assert result.features == {"domain_age_days": 2192, "is_shortener": 0, "registrar_known": 1}
    assert all(type(v) is int for v in result.features.values())
    assert result.status == "ok"
    assert result.whois_skipped is False
    assert rec.calls == ["example.com"]


def test_cache_hit_then_ttl_expiry_recomputes_age() -> None:
    clock = FakeClock(START)
    rec = Recorder()
    ex = make(rec, clock)
    assert run(ex, "http://example.com/").features["domain_age_days"] == 2192
    second = run(ex, "http://example.com/other")
    got = (second.status, second.features["domain_age_days"], len(rec.calls))
    assert got == ("cached", 2192, 1)
    clock.advance(86_401)
    third = run(ex, "http://example.com/")
    assert (third.status, third.features["domain_age_days"], len(rec.calls)) == ("ok", 2193, 2)


def test_cache_is_shared_across_subdomains() -> None:
    rec = Recorder()
    ex = make(rec)
    run(ex, "http://a.example.com/")
    run(ex, "http://b.example.com/")
    assert rec.calls == ["example.com"]


def test_lookup_exception_degrades_and_is_negatively_cached() -> None:
    clock = FakeClock(START)
    rec = Recorder(error=RuntimeError("boom"))
    ex = make(rec, clock)
    with capture_logs() as logs:
        first = run(ex, "http://example.com/")
        second = run(ex, "http://example.com/")
    assert first.features == SENTINELS
    assert (first.status, first.whois_skipped) == ("failed", False)
    assert second.status == "cached"
    assert len(rec.calls) == 1
    assert failures(logs) == ["lookup_failed"]
    clock.advance(601)
    run(ex, "http://example.com/")
    assert len(rec.calls) == 2


def test_empty_record_counts_as_failure() -> None:
    ex = make(Recorder(record=WhoisRecord(None, None)))
    with capture_logs() as logs:
        result = run(ex, "http://example.com/")
    assert (result.status, result.features) == ("failed", SENTINELS)
    assert failures(logs) == ["empty_record"]


def test_registrar_without_creation_date() -> None:
    result = run(make(Recorder(record=WhoisRecord(None, "Acme"))), "http://example.com/")
    assert result.features == {"domain_age_days": -1, "is_shortener": 0, "registrar_known": 1}
    assert result.status == "ok"


def test_future_creation_date_is_unknown_age() -> None:
    future = WhoisRecord(START + timedelta(days=5), "Acme")
    result = run(make(Recorder(record=future)), "http://example.com/")
    assert result.features["domain_age_days"] == -1
    assert result.features["registrar_known"] == 1


def test_disabled_skips_whois_but_keeps_shortener_flag() -> None:
    rec = Recorder()
    ex = make(rec, whois_disabled=True)
    result = run(ex, "http://bit.ly/abc")
    assert result.features == {"domain_age_days": -1, "is_shortener": 1, "registrar_known": 0}
    assert (result.status, result.whois_skipped) == ("disabled", True)
    assert rec.calls == []


@pytest.mark.parametrize(
    "raw", ["http://192.0.2.1/x", "http://[2001:db8::1]/", "http://localhost/x"]
)
def test_not_applicable_hosts(raw: str) -> None:
    rec = Recorder()
    result = run(make(rec), raw)
    assert result.features == SENTINELS
    assert (result.status, result.whois_skipped) == ("not_applicable", False)
    assert rec.calls == []


@pytest.mark.parametrize("budget", [0.0, -1.0])
def test_exhausted_budget_skips_the_lookup(budget: float) -> None:
    rec = Recorder()
    result = run(make(rec), "http://example.com/", timeout_seconds=budget)
    assert (result.status, result.whois_skipped, result.features) == (
        "budget_exhausted",
        True,
        SENTINELS,
    )
    assert rec.calls == []


def test_budget_shortens_the_timeout_and_late_result_warms_the_cache(
    gate: threading.Event,
) -> None:
    rec = Recorder(gate=gate)
    ex = make(rec, default_timeout_seconds=2.0)
    started = time.monotonic()
    with capture_logs() as logs:
        result = run(ex, "http://example.com/", timeout_seconds=0.05)
    assert time.monotonic() - started < 1.0
    assert (result.status, result.whois_skipped, result.features) == ("timeout", True, SENTINELS)
    assert failures(logs) == ["timeout"]
    assert run(ex, "http://example.com/").status == "cached"  # negative entry, no new thread
    assert len(rec.calls) == 1
    gate.set()
    wait_for(lambda: ex.active_lookups == 0)
    warmed = run(ex, "http://example.com/")
    assert (warmed.status, warmed.features["domain_age_days"]) == ("cached", 2192)
    assert warmed.features["registrar_known"] == 1


def test_default_timeout_applies_without_a_budget(gate: threading.Event) -> None:
    ex = make(Recorder(gate=gate), default_timeout_seconds=0.05)
    assert run(ex, "http://example.com/").status == "timeout"


def test_saturation_skips_instead_of_queueing(gate: threading.Event) -> None:
    rec = Recorder(gate=gate)
    ex = make(rec, max_workers=2)
    assert run(ex, "http://a.com/", timeout_seconds=0.05).status == "timeout"
    assert run(ex, "http://b.com/", timeout_seconds=0.05).status == "timeout"
    assert ex.active_lookups == 2
    with capture_logs() as logs:
        blocked = run(ex, "http://c.com/", timeout_seconds=0.05)
    assert (blocked.status, blocked.whois_skipped, blocked.features) == (
        "saturated",
        True,
        SENTINELS,
    )
    assert failures(logs) == ["saturated"]
    assert sorted(rec.calls) == ["a.com", "b.com"]
    gate.set()
    wait_for(lambda: ex.active_lookups == 0)
    assert run(ex, "http://c.com/").status == "ok"  # saturation is not cached


def test_fake_delay_hook_delays_the_lookup() -> None:
    rec = Recorder()
    ex = make(rec, fake_delay_seconds=0.3)
    started = time.monotonic()
    result = run(ex, "http://example.com/", timeout_seconds=0.05)
    assert time.monotonic() - started < 0.25
    assert result.status == "timeout"
    assert rec.calls == []
    wait_for(lambda: ex.active_lookups == 0)
    assert rec.calls == ["example.com"]


def test_from_settings_honours_the_test_only_fake_delay() -> None:
    test_env = Settings(
        _env_file=None,
        app_env="test",
        whois_fake_delay_seconds=3.0,
        whois_disabled=True,
        whois_timeout_seconds=1.5,
    )
    ex = HostFeatureExtractor.from_settings(test_env, FakeClock())
    got = (ex.fake_delay_seconds, ex.whois_disabled, ex.default_timeout_seconds)
    assert got == (3.0, True, 1.5)
    dev = Settings(_env_file=None, app_env="dev", whois_fake_delay_seconds=3.0)
    assert HostFeatureExtractor.from_settings(dev, FakeClock()).fake_delay_seconds == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [{"default_timeout_seconds": 0}, {"max_workers": 0}, {"fake_delay_seconds": -1}],
)
def test_constructor_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be"):
        HostFeatureExtractor(clock=FakeClock(), **kwargs)
