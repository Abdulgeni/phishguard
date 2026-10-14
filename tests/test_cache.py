import threading

import pytest

from app.services.cache import TtlLruCache
from app.services.clock import FakeClock


def make(max_entries: int = 3) -> tuple[TtlLruCache[int], FakeClock]:
    clock = FakeClock()
    return TtlLruCache[int](max_entries=max_entries, clock=clock), clock


def test_set_get_and_miss() -> None:
    cache, _ = make()
    assert cache.get("a") is None
    cache.set("a", 1, 10)
    assert cache.get("a") == 1
    assert len(cache) == 1


def test_entry_expires_at_ttl() -> None:
    cache, clock = make()
    cache.set("a", 1, 10)
    clock.advance(9.99)
    assert cache.get("a") == 1
    clock.advance(0.02)
    assert cache.get("a") is None
    assert len(cache) == 0


def test_lru_eviction_prefers_least_recently_used() -> None:
    cache, _ = make(max_entries=2)
    cache.set("a", 1, 10)
    cache.set("b", 2, 10)
    assert cache.get("a") == 1  # touch a, so b is now the oldest
    cache.set("c", 3, 10)
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3


def test_set_refreshes_ttl() -> None:
    cache, clock = make()
    cache.set("a", 1, 10)
    clock.advance(8)
    cache.set("a", 2, 10)
    clock.advance(8)
    assert cache.get("a") == 2


def test_set_if_absent() -> None:
    cache, clock = make()
    assert cache.set_if_absent("a", 1, 10) is True
    assert cache.set_if_absent("a", 2, 10) is False
    assert cache.get("a") == 1
    clock.advance(11)
    assert cache.set_if_absent("a", 3, 10) is True
    assert cache.get("a") == 3


def test_invalid_arguments() -> None:
    with pytest.raises(ValueError, match="max_entries"):
        TtlLruCache[int](max_entries=0, clock=FakeClock())
    cache, _ = make()
    with pytest.raises(ValueError, match="ttl_seconds"):
        cache.set("a", 1, 0)
    with pytest.raises(ValueError, match="ttl_seconds"):
        cache.set_if_absent("a", 1, -1)


def test_thread_safety_smoke() -> None:
    cache, _ = make(max_entries=10)
    errors: list[BaseException] = []

    def worker(seed: int) -> None:
        try:
            for i in range(500):
                key = f"k{(seed + i) % 20}"
                cache.set(key, i, 100)
                cache.get(key)
                cache.set_if_absent(f"x{i % 5}", i, 100)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(cache) <= 10
