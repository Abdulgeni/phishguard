"""Injectable time source. All 'now' reads in the app go through a Clock."""

import time
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime:
        """Timezone-aware UTC wall-clock time (timestamps, model version)."""
        ...

    def monotonic(self) -> float:
        """Seconds on a monotonic scale; only differences are meaningful (budgets, TTLs)."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class FakeClock:
    """Deterministic clock for tests; time only moves via advance()."""

    def __init__(self, start: datetime | None = None) -> None:
        self._start = start if start is not None else datetime(2026, 1, 1, tzinfo=UTC)
        if self._start.tzinfo is None:
            raise ValueError("start must be timezone-aware")
        self._elapsed = 0.0

    def now(self) -> datetime:
        return self._start + timedelta(seconds=self._elapsed)

    def monotonic(self) -> float:
        return self._elapsed

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance by a negative amount")
        self._elapsed += seconds
