"""Feature pipeline: one deterministic, ordered dict of 20 features per URL.

Two responsibilities:

* :class:`Budget` — a per-request time budget driven by the injectable ``Clock``.
* :func:`extract_features` — orchestrates lexical (pure) and host (WHOIS-touching)
  extraction into a single, contract-ordered ``dict[str, int]``.

The order and names of ``FEATURE_NAMES`` are frozen at this step. Downstream
code (training, inference, response shaping, the model card) must treat them as
the single source of truth.

No ``None`` value can appear in the output: every sub-extractor already converts
unknowns to sentinels (``-1`` for numeric, ``0`` for boolean).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from app.features.host import HOST_FEATURE_NAMES, HostFeatureExtractor
from app.features.lexical import LEXICAL_FEATURE_NAMES, extract_lexical
from app.features.normalize import NormalizedUrl
from app.services.clock import Clock

# Frozen contract: 17 lexical + 3 host, in this exact order.
FEATURE_NAMES: Final[tuple[str, ...]] = LEXICAL_FEATURE_NAMES + HOST_FEATURE_NAMES

assert len(FEATURE_NAMES) == 20, f"expected 20 features, got {len(FEATURE_NAMES)}"
assert len(set(FEATURE_NAMES)) == 20, "duplicate feature names in the contract"


@dataclass(frozen=True, slots=True)
class Budget:
    """Per-request time budget, measured on the injectable ``Clock``.

    The budget is created once when a request arrives and shared by every step
    that can consume time. ``remaining()`` never returns a negative number: when
    the budget is exhausted, it returns ``0.0`` so callers can branch on
    ``remaining() <= 0`` without worrying about sign.
    """

    _clock: Clock
    _started_mono: float
    _limit_seconds: float

    @classmethod
    def start(cls, clock: Clock, limit_seconds: float) -> "Budget":
        if limit_seconds <= 0:
            raise ValueError("limit_seconds must be > 0")
        return cls(_clock=clock, _started_mono=clock.monotonic(), _limit_seconds=limit_seconds)

    @property
    def limit_seconds(self) -> float:
        return self._limit_seconds

    def elapsed(self) -> float:
        return max(0.0, self._clock.monotonic() - self._started_mono)

    def remaining(self) -> float:
        return max(0.0, self._limit_seconds - self.elapsed())

    def exhausted(self) -> bool:
        return self.remaining() <= 0.0


def extract_features(
    url: NormalizedUrl,
    *,
    budget: Budget,
    host_extractor: HostFeatureExtractor,
) -> dict[str, int]:
    """Return the 20 contract features for ``url`` in ``FEATURE_NAMES`` order.

    Lexical features are pure and instant. Host features consult the request
    budget: if the budget is already exhausted, WHOIS is skipped and only
    ``is_shortener`` carries real signal.
    """
    lexical = extract_lexical(url)
    host = host_extractor.extract(url, timeout_seconds=budget.remaining()).features
    merged: dict[str, int] = {**lexical, **host}
    ordered = {name: merged[name] for name in FEATURE_NAMES}
    return ordered


def assert_contract(features: Mapping[str, int]) -> None:
    """Fail loudly if ``features`` is not exactly the frozen 20-key contract."""
    if tuple(features) != FEATURE_NAMES:
        raise ValueError(
            f"feature contract violation: expected {FEATURE_NAMES!r}, got {tuple(features)!r}"
        )
    for name, value in features.items():
        if type(value) is not int:
            raise TypeError(f"feature {name!r} must be int, got {type(value).__name__}")
