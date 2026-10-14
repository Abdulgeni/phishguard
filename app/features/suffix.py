"""Shared offline public-suffix extractor.

``tldextract`` fetches the public suffix list over the network by default. We
never want that: it breaks offline Docker, it slows the first call, and it
violates the "no network on untrusted input" rule. We construct it with the
bundled snapshot and disable the on-disk cache, so it is fully deterministic
and offline.

This module exists so both ``lexical`` and ``host`` share one instance, instead
of one reaching into the other's private namespace.
"""

from functools import lru_cache
from typing import Final

from tldextract import TLDExtract

_MAX_LABEL_LENGTH: Final = 63


@lru_cache(maxsize=1)
def extractor() -> TLDExtract:
    """Process-wide, offline-only public-suffix extractor."""
    return TLDExtract(suffix_list_urls=(), cache_dir=None)


def registered_domain(host: str) -> str | None:
    """Return ``example.co.uk`` for a host, or None if it has no public suffix."""
    try:
        extracted = extractor()(host)
        domain = str(extracted.domain)
        suffix = str(extracted.suffix)
    except Exception:  # third-party parser on untrusted input: degrade, never raise
        return None
    return f"{domain}.{suffix}".lower() if domain and suffix else None
