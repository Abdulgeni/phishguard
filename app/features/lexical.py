"""Lexical URL features: pure functions over a normalized URL (no I/O, no network)."""

import re
import string
from functools import lru_cache
from importlib.resources import files
from typing import Final

from app.features.normalize import NormalizedUrl
from app.features.suffix import extractor

UNKNOWN: Final = -1

# Frozen contract (decision 2, minus has_https per flaw 5): exact names, exact order.
LEXICAL_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "url_length",
    "host_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_slashes",
    "num_query_params",
    "num_subdomains",
    "has_ip_host",
    "has_at_symbol",
    "has_punycode",
    "tld_length",
    "path_depth",
    "suspicious_keyword_hits",
    "has_double_slash_in_path",
    "has_hex_encoding",
)

_HEX_RE: Final = re.compile(r"%[0-9A-Fa-f]{2}")
_DIGITS: Final = frozenset(string.digits)
_KEYWORDS_FILE: Final = "suspicious_keywords.txt"


@lru_cache(maxsize=1)
def load_suspicious_keywords() -> tuple[str, ...]:
    resource = files("app.features").joinpath("data").joinpath(_KEYWORDS_FILE)
    words: list[str] = []
    for line in resource.read_text(encoding="utf-8").splitlines():
        word = line.split("#", 1)[0].strip().lower()
        if word and word not in words:
            words.append(word)
    if not words:
        raise ValueError(f"{_KEYWORDS_FILE} contains no keywords")
    return tuple(words)


def _domain_parts(host: str, is_ip: bool) -> tuple[int, int]:
    """Return (num_subdomains, tld_length); (-1, -1) when unknowable."""
    if is_ip:
        return UNKNOWN, UNKNOWN
    try:
        extracted = extractor()(host)
        suffix = str(extracted.suffix)
        subdomain = str(extracted.subdomain)
    except Exception:  # third-party parser on untrusted input: degrade, never raise
        return UNKNOWN, UNKNOWN
    if not suffix:
        return UNKNOWN, UNKNOWN
    labels = [label for label in subdomain.split(".") if label]
    return len(labels), len(suffix)


def _count_digits(text: str) -> int:
    return sum(1 for ch in text if ch in _DIGITS)


def _query_param_count(query: str) -> int:
    return sum(1 for part in query.split("&") if part)


def _path_depth(path: str) -> int:
    return sum(1 for segment in path.split("/") if segment)


def _keyword_hits(url_text: str) -> int:
    lowered = url_text.lower()
    return sum(1 for word in load_suspicious_keywords() if word in lowered)


def _has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def extract_lexical(url: NormalizedUrl) -> dict[str, int]:
    """Compute the 17 lexical features, in contract order, all plain ints."""
    full = url.url
    num_subdomains, tld_length = _domain_parts(url.host, url.is_ip_host)
    values = (
        len(full),
        len(url.host),
        len(url.path),
        full.count("."),
        full.count("-"),
        _count_digits(full),
        full.count("/"),
        _query_param_count(url.query),
        num_subdomains,
        int(url.is_ip_host),
        int("@" in full),
        int(_has_punycode(url.host)),
        tld_length,
        _path_depth(url.path),
        _keyword_hits(full),
        int("//" in url.path),
        int(_HEX_RE.search(full) is not None),
    )
    return dict(zip(LEXICAL_FEATURE_NAMES, values, strict=True))
