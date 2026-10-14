"""Thread-safe LRU cache with per-entry TTL, driven by an injectable Clock."""

import threading
from collections import OrderedDict
from typing import Generic, TypeVar

from app.services.clock import Clock

V = TypeVar("V")


class TtlLruCache(Generic[V]):
    """String-keyed cache. ``get`` returns None on a miss, so None is not a storable value.

    TTLs use ``Clock.monotonic()``. ``len()`` may include expired entries that have
    not been touched since they expired; they are purged lazily on access.
    """

    def __init__(self, *, max_entries: int, clock: Clock) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._clock = clock
        self._items: OrderedDict[str, tuple[float, V]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> V | None:
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock.monotonic() >= expires_at:
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return value

    def set(self, key: str, value: V, ttl_seconds: float) -> None:
        self._check_ttl(ttl_seconds)
        with self._lock:
            self._put(key, value, ttl_seconds)

    def set_if_absent(self, key: str, value: V, ttl_seconds: float) -> bool:
        """Store only if there is no live entry. Returns True if stored."""
        self._check_ttl(ttl_seconds)
        with self._lock:
            entry = self._items.get(key)
            if entry is not None and self._clock.monotonic() < entry[0]:
                return False
            self._put(key, value, ttl_seconds)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    @staticmethod
    def _check_ttl(ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")

    def _put(self, key: str, value: V, ttl_seconds: float) -> None:
        self._items[key] = (self._clock.monotonic() + ttl_seconds, value)
        self._items.move_to_end(key)
        while len(self._items) > self._max_entries:
            self._items.popitem(last=False)
