"""Extract candidate URLs from a raw email body.

Strategy: plain regex, no HTML parsing, no attachment handling. The goal is a
best-effort list of URLs that we then score with the same predictor as
``/predict``. Anything that fails to normalize is silently dropped: the body is
prose, and a malformed candidate is not a client error.
"""

import re
from typing import Final
from urllib.parse import urlsplit

from app.features.normalize import InvalidUrlError, normalize_url

# http:// or https:// followed by non-whitespace, non-quote characters.
_HTTP_URL_RE: Final = re.compile(
    r"https?://[^\s<>\"'\)\]\}]+",
    re.IGNORECASE,
)
# www.something.tld (no scheme) with a plausible host.
_WWW_URL_RE: Final = re.compile(
    r"(?<![\w./])www\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?:/[^\s<>\"'\)\]\}]*)?",
    re.IGNORECASE,
)


def extract_urls(body: str, *, max_urls: int) -> tuple[list[str], bool]:
    """Return ``(urls, truncated)``.

    URLs are returned in first-seen order, deduplicated by *normalized* form.
    The list is capped at ``max_urls``; if more were found, ``truncated`` is True.

    URLs that fail normalization are dropped.
    """
    if max_urls < 1:
        raise ValueError("max_urls must be >= 1")

    candidates: list[str] = []
    candidates.extend(match.group(0) for match in _HTTP_URL_RE.finditer(body))
    candidates.extend(match.group(0) for match in _WWW_URL_RE.finditer(body))

    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate.startswith("www."):
            candidate = "http://" + candidate
        try:
            normalized = normalize_url(candidate).url
        except InvalidUrlError:
            continue
        # Treat "http://example.com" and "http://example.com/" as the same URL
        # for dedup purposes. We do this here, not in normalize_url, because
        # normalize_url is on the frozen training contract and changing it
        # would invalidate the trained model.
        key = _dedup_key(normalized)
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)

    if len(unique) > max_urls:
        return unique[:max_urls], True
    return unique, False


def host_of(url: str) -> str:
    """Return the host of a URL string, or '' if unparseable. Never raises."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _dedup_key(normalized_url: str) -> str:
    """Normalize away the bare-host trailing slash for dedup only.

    ``http://example.com`` and ``http://example.com/`` are the same page; we
    collapse them so the same URL is not scored twice. We do this here rather
    than in ``normalize_url`` because the latter is on the frozen feature
    contract, and changing it would invalidate the trained model.
    """
    parts = urlsplit(normalized_url)
    if parts.path in ("", "/") and not parts.query and not parts.fragment:
        return parts._replace(path="").geturl()
    return normalized_url
