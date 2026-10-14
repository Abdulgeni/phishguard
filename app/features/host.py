"""Host-based features: static shortener lookup + best-effort WHOIS.

WHOIS is never allowed to hurt a request: every failure path (disabled, budget, timeout,
saturation, lookup error, empty record, IP host) yields sentinels, never an exception.

Lookups run in daemon threads, at most ``max_workers`` at a time. A timed-out lookup
cannot be killed; it keeps its slot until it returns (so hung lookups count toward the
cap) and its late result still warms the cache. Daemon threads never block shutdown.
Concurrent lookups for the same uncached domain are not deduplicated.
"""

import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any, Final, Literal

import structlog

from app.config import Settings
from app.features.normalize import NormalizedUrl
from app.features.suffix import registered_domain as _registered_domain
from app.services.cache import TtlLruCache
from app.services.clock import Clock

UNKNOWN_AGE: Final = -1

# Frozen contract (decision 2): exact names, exact order.
HOST_FEATURE_NAMES: Final[tuple[str, ...]] = ("domain_age_days", "is_shortener", "registrar_known")

DEFAULT_MAX_WORKERS: Final = 8
DEFAULT_CACHE_SIZE: Final = 10_000
SUCCESS_TTL_SECONDS: Final = 24 * 60 * 60.0
FAILURE_TTL_SECONDS: Final = 10 * 60.0

WhoisStatus = Literal[
    "ok",
    "cached",
    "failed",
    "timeout",
    "saturated",
    "budget_exhausted",
    "disabled",
    "not_applicable",
]
_SKIPPED: Final[frozenset[str]] = frozenset(
    {"timeout", "saturated", "budget_exhausted", "disabled"}
)

log = structlog.get_logger("phishguard.whois")


@dataclass(frozen=True, slots=True)
class WhoisRecord:
    creation_date: datetime | None  # timezone-aware UTC
    registrar: str | None


@dataclass(frozen=True, slots=True)
class HostResult:
    features: dict[str, int]  # keys == HOST_FEATURE_NAMES, in order
    status: WhoisStatus

    @property
    def whois_skipped(self) -> bool:
        """True when WHOIS did not complete (disabled, budget, timeout, saturated)."""
        return self.status in _SKIPPED


@dataclass(frozen=True, slots=True)
class _Outcome:
    record: WhoisRecord | None  # None = failed lookup


LookupFn = Callable[[str], WhoisRecord]


# --- static shortener list -------------------------------------------------------------


@lru_cache(maxsize=1)
def load_shorteners() -> frozenset[str]:
    resource = files("app.features").joinpath("data").joinpath("shorteners.txt")
    domains = {
        line.split("#", 1)[0].strip().lower()
        for line in resource.read_text(encoding="utf-8").splitlines()
    }
    domains.discard("")
    if not domains:
        raise ValueError("shorteners.txt contains no domains")
    return frozenset(domains)


def is_shortener(host: str) -> bool:
    """True if ``host`` equals, or is a subdomain of, a listed shortener. No network."""
    labels = host.lower().split(".")
    shorteners = load_shorteners()
    return any(".".join(labels[i:]) in shorteners for i in range(len(labels) - 1))


def registered_domain(host: str) -> str | None:
    """Registered domain (``example.co.uk``), or None if the host has no public suffix.

    Thin alias around :func:`app.features.suffix.registered_domain` so callers
    of ``host`` do not need to import the suffix module directly.
    """
    return _registered_domain(host)


# --- WHOIS parsing and the real lookup ---------------------------------------------------


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _to_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return _as_utc(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, str):
        try:
            return _as_utc(datetime.fromisoformat(value.strip()))
        except ValueError:
            return None
    return None


def _first_datetime(value: object) -> datetime | None:
    items = value if isinstance(value, list | tuple) else [value]
    parsed = [dt for item in items if (dt := _to_datetime(item)) is not None]
    return min(parsed) if parsed else None


def _first_str(value: object) -> str | None:
    items = value if isinstance(value, list | tuple) else [value]
    for item in items:
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def parse_whois_response(data: Mapping[str, Any]) -> WhoisRecord:
    """Tolerant parser: creation_date may be a list/str/date/None; registrar a list/str."""
    return WhoisRecord(
        creation_date=_first_datetime(data.get("creation_date")),
        registrar=_first_str(data.get("registrar")),
    )


def python_whois_lookup(domain: str) -> WhoisRecord:
    """The real lookup via python-whois (blocking network I/O; run it in a thread)."""
    import whois  # lazy: keeps import time and test isolation cheap

    return parse_whois_response(whois.whois(domain))


def _log_failure(domain: str, reason: str, **extra: str) -> None:
    log.warning("whois_failed", reason=reason, domain=domain, **extra)


# --- extractor -----------------------------------------------------------------------------


class HostFeatureExtractor:
    def __init__(
        self,
        *,
        clock: Clock,
        lookup: LookupFn | None = None,
        whois_disabled: bool = False,
        default_timeout_seconds: float = 2.0,
        fake_delay_seconds: float = 0.0,
        max_workers: int = DEFAULT_MAX_WORKERS,
        cache_size: int = DEFAULT_CACHE_SIZE,
        success_ttl_seconds: float = SUCCESS_TTL_SECONDS,
        failure_ttl_seconds: float = FAILURE_TTL_SECONDS,
    ) -> None:
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be > 0")
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if fake_delay_seconds < 0:
            raise ValueError("fake_delay_seconds must be >= 0")
        self._clock = clock
        self._lookup: LookupFn = lookup if lookup is not None else python_whois_lookup
        self.whois_disabled = whois_disabled
        self.default_timeout_seconds = default_timeout_seconds
        self.fake_delay_seconds = fake_delay_seconds  # test hook; see from_settings
        self._max_workers = max_workers
        self._success_ttl = success_ttl_seconds
        self._failure_ttl = failure_ttl_seconds
        self._cache: TtlLruCache[_Outcome] = TtlLruCache(max_entries=cache_size, clock=clock)
        self._active = 0
        self._active_lock = threading.Lock()

    @classmethod
    def from_settings(
        cls, settings: Settings, clock: Clock, *, lookup: LookupFn | None = None
    ) -> "HostFeatureExtractor":
        return cls(
            clock=clock,
            lookup=lookup,
            whois_disabled=settings.whois_disabled,
            default_timeout_seconds=settings.whois_timeout_seconds,
            fake_delay_seconds=settings.whois_fake_delay_effective,  # 0 unless APP_ENV=test
        )

    @property
    def active_lookups(self) -> int:
        with self._active_lock:
            return self._active

    def extract(self, url: NormalizedUrl, *, timeout_seconds: float | None = None) -> HostResult:
        """Compute the 3 host features. ``timeout_seconds`` is the remaining request budget."""
        shortener = int(not url.is_ip_host and is_shortener(url.host))
        if self.whois_disabled:
            return self._build(shortener, None, "disabled")
        domain = None if url.is_ip_host else registered_domain(url.host)
        if domain is None:
            return self._build(shortener, None, "not_applicable")
        cached = self._cache.get(domain)
        if cached is not None:
            return self._build(shortener, cached.record, "cached")
        timeout = self._effective_timeout(timeout_seconds)
        if timeout <= 0:
            return self._build(shortener, None, "budget_exhausted")
        record, status = self._lookup_bounded(domain, timeout)
        return self._build(shortener, record, status)

    def _effective_timeout(self, budget_seconds: float | None) -> float:
        if budget_seconds is None:
            return self.default_timeout_seconds
        return min(self.default_timeout_seconds, budget_seconds)

    def _lookup_bounded(
        self, domain: str, timeout: float
    ) -> tuple[WhoisRecord | None, WhoisStatus]:
        future = self._spawn(domain)
        if future is None:
            _log_failure(domain, "saturated")
            return None, "saturated"
        try:
            outcome = future.result(timeout=timeout)
        except TimeoutError:
            self._cache.set_if_absent(domain, _Outcome(None), self._failure_ttl)
            _log_failure(domain, "timeout")
            return None, "timeout"
        return outcome.record, ("ok" if outcome.record is not None else "failed")

    def _spawn(self, domain: str) -> "Future[_Outcome] | None":
        if not self._try_acquire():
            return None
        future: Future[_Outcome] = Future()
        thread = threading.Thread(
            target=self._work, args=(domain, future), name="whois-lookup", daemon=True
        )
        try:
            thread.start()
        except RuntimeError:
            self._release()
            _log_failure(domain, "thread_start_failed")
            future.set_result(_Outcome(None))
        return future

    def _work(self, domain: str, future: "Future[_Outcome]") -> None:
        try:
            outcome = self._lookup_outcome(domain)
            ttl = self._success_ttl if outcome.record is not None else self._failure_ttl
            self._cache.set(domain, outcome, ttl)  # overwrites a timeout's negative entry
            future.set_result(outcome)
        finally:
            self._release()

    def _lookup_outcome(self, domain: str) -> _Outcome:
        try:
            if self.fake_delay_seconds > 0:
                time.sleep(self.fake_delay_seconds)
            record = self._lookup(domain)
        except Exception as exc:  # any lookup failure degrades; it must never escape the thread
            _log_failure(domain, "lookup_failed", error=type(exc).__name__)
            return _Outcome(None)
        if record.creation_date is None and record.registrar is None:
            _log_failure(domain, "empty_record")
            return _Outcome(None)
        return _Outcome(record)

    def _try_acquire(self) -> bool:
        with self._active_lock:
            if self._active >= self._max_workers:
                return False
            self._active += 1
            return True

    def _release(self) -> None:
        with self._active_lock:
            self._active -= 1

    def _build(self, shortener: int, record: WhoisRecord | None, status: WhoisStatus) -> HostResult:
        features = {
            "domain_age_days": self._age_days(record),
            "is_shortener": shortener,
            "registrar_known": int(record is not None and record.registrar is not None),
        }
        return HostResult(features=features, status=status)

    def _age_days(self, record: WhoisRecord | None) -> int:
        if record is None or record.creation_date is None:
            return UNKNOWN_AGE
        days = (self._clock.now() - record.creation_date).days
        return days if days >= 0 else UNKNOWN_AGE  # future creation date = unknown
