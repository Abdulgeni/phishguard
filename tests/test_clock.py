import time
from datetime import UTC, datetime

import pytest

from app.services.clock import Clock, FakeClock, SystemClock


def test_system_clock_is_utc_aware_and_monotonic() -> None:
    clock = SystemClock()
    assert clock.now().tzinfo is not None
    assert clock.now().utcoffset() is not None
    a = clock.monotonic()
    time.sleep(0.001)
    assert clock.monotonic() >= a


def test_fake_clock_advances_both_reads() -> None:
    clock = FakeClock(datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC))
    assert clock.monotonic() == 0.0
    clock.advance(90)
    assert clock.monotonic() == 90.0
    assert clock.now() == datetime(2026, 3, 4, 5, 7, 37, tzinfo=UTC)


def test_fake_clock_rejects_negative_advance_and_naive_start() -> None:
    with pytest.raises(ValueError, match="negative"):
        FakeClock().advance(-1)
    with pytest.raises(ValueError, match="timezone-aware"):
        FakeClock(datetime(2026, 1, 1))


def test_both_implementations_satisfy_protocol() -> None:
    assert isinstance(SystemClock(), Clock)
    assert isinstance(FakeClock(), Clock)
