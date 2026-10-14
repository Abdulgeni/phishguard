import random
from datetime import UTC, datetime

import pytest

from app.features.host import HOST_FEATURE_NAMES, HostFeatureExtractor, WhoisRecord
from app.features.lexical import LEXICAL_FEATURE_NAMES
from app.features.normalize import InvalidUrlError, normalize_url
from app.features.pipeline import (
    FEATURE_NAMES,
    Budget,
    assert_contract,
    extract_features,
)
from app.services.clock import FakeClock

START = datetime(2026, 1, 1, tzinfo=UTC)
RECORD = WhoisRecord(creation_date=datetime(2020, 1, 1, tzinfo=UTC), registrar="Acme")


def fake_extractor(record: WhoisRecord = RECORD) -> HostFeatureExtractor:
    def lookup(_domain: str) -> WhoisRecord:
        return record

    return HostFeatureExtractor(clock=FakeClock(START), lookup=lookup)


def test_feature_names_are_the_frozen_20_in_order() -> None:
    expected = LEXICAL_FEATURE_NAMES + HOST_FEATURE_NAMES
    assert expected == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 20
    assert len(set(FEATURE_NAMES)) == 20
    assert "has_https" not in FEATURE_NAMES


def test_extract_returns_keys_in_contract_order() -> None:
    clock = FakeClock(START)
    out = extract_features(
        normalize_url("http://example.com/login"),
        budget=Budget.start(clock, 3.0),
        host_extractor=fake_extractor(),
    )
    assert tuple(out) == FEATURE_NAMES
    assert all(type(v) is int for v in out.values())
    assert_contract(out)


def test_budget_starts_full_and_decreases_with_clock() -> None:
    clock = FakeClock(START)
    budget = Budget.start(clock, 3.0)
    assert budget.remaining() == pytest.approx(3.0)
    assert budget.elapsed() == pytest.approx(0.0)
    clock.advance(1.2)
    assert budget.remaining() == pytest.approx(1.8)
    assert budget.elapsed() == pytest.approx(1.2)


def test_budget_clamps_at_zero_and_reports_exhausted() -> None:
    clock = FakeClock(START)
    budget = Budget.start(clock, 2.0)
    clock.advance(5.0)
    assert budget.remaining() == 0.0
    assert budget.exhausted() is True


def test_budget_rejects_non_positive_limit() -> None:
    clock = FakeClock(START)
    with pytest.raises(ValueError, match="limit_seconds"):
        Budget.start(clock, 0.0)
    with pytest.raises(ValueError, match="limit_seconds"):
        Budget.start(clock, -1.0)


def test_exhausted_budget_skips_whois_but_keeps_shortener() -> None:
    clock = FakeClock(START)
    budget = Budget.start(clock, 1.0)
    clock.advance(2.0)
    out = extract_features(
        normalize_url("http://bit.ly/xyz"),
        budget=budget,
        host_extractor=fake_extractor(),
    )
    assert out["is_shortener"] == 1
    assert out["domain_age_days"] == -1
    assert out["registrar_known"] == 0


def test_full_budget_allows_whois_to_succeed() -> None:
    clock = FakeClock(START)
    out = extract_features(
        normalize_url("http://example.com/"),
        budget=Budget.start(clock, 3.0),
        host_extractor=fake_extractor(),
    )
    assert out["domain_age_days"] > 0
    assert out["registrar_known"] == 1
    assert out["is_shortener"] == 0


def test_pure_for_the_same_inputs() -> None:
    clock = FakeClock(START)
    url = normalize_url("http://example.com/login?next=/x")
    ex = fake_extractor()
    first = extract_features(url, budget=Budget.start(clock, 3.0), host_extractor=ex)
    second = extract_features(url, budget=Budget.start(clock, 3.0), host_extractor=ex)
    assert first == second


def test_ip_host_gives_host_sentinels_and_contract_holds() -> None:
    clock = FakeClock(START)
    out = extract_features(
        normalize_url("http://192.0.2.1/login"),
        budget=Budget.start(clock, 3.0),
        host_extractor=fake_extractor(),
    )
    assert out["has_ip_host"] == 1
    assert out["domain_age_days"] == -1
    assert out["registrar_known"] == 0
    assert_contract(out)


def test_shortener_flag_survives_whois_failure() -> None:
    def failing(_domain: str) -> WhoisRecord:
        raise RuntimeError("boom")

    ex = HostFeatureExtractor(clock=FakeClock(START), lookup=failing)
    clock = FakeClock(START)
    out = extract_features(
        normalize_url("http://bit.ly/xyz"),
        budget=Budget.start(clock, 3.0),
        host_extractor=ex,
    )
    assert out["is_shortener"] == 1
    assert out["domain_age_days"] == -1


_ALPHABET = "ahttp:/.@[]%#?&=-_ 0123456789ü。\u202e\x00\ud800"
_PREFIXES = ["", "http://", "https://a.", "//"]


def test_fuzz_preserves_contract() -> None:
    rng = random.Random(7)
    clock = FakeClock(START)
    ex = fake_extractor()
    checked = 0
    for _ in range(1000):
        body = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 60)))
        try:
            url = normalize_url(rng.choice(_PREFIXES) + body)
        except InvalidUrlError:
            continue
        out = extract_features(url, budget=Budget.start(clock, 3.0), host_extractor=ex)
        assert tuple(out) == FEATURE_NAMES
        assert_contract(out)
        checked += 1
    assert checked > 0


def test_assert_contract_rejects_missing_key() -> None:
    bad = dict.fromkeys(FEATURE_NAMES[:-1], 0)
    with pytest.raises(ValueError, match="feature contract violation"):
        assert_contract(bad)


def test_assert_contract_rejects_extra_key() -> None:
    bad = dict.fromkeys(FEATURE_NAMES, 0)
    bad["extra"] = 0
    with pytest.raises(ValueError, match="feature contract violation"):
        assert_contract(bad)


def test_assert_contract_rejects_non_int() -> None:
    bad = dict.fromkeys(FEATURE_NAMES, 0)
    bad[FEATURE_NAMES[0]] = 1.5  # type: ignore[assignment]
    with pytest.raises(TypeError, match="must be int"):
        assert_contract(bad)
