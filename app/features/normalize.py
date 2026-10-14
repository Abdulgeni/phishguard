"""URL normalization shared by training and serving.

Every URL, from the dataset or from a request, passes through ``normalize_url``
before features are computed, so train and serve see the same form. The input is
untrusted: any problem raises ``InvalidUrlError`` and nothing else escapes.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Final
from urllib.parse import SplitResult, urlsplit

import idna

DEFAULT_MAX_URL_LENGTH: Final = 2048

_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
_SCHEME_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
# "mailto:x", "javascript:x" (but not "host:8080/path")
_OPAQUE_SCHEME_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:(?!\d+(?:[/?#]|$))")
_LABEL_RE: Final = re.compile(r"[a-z0-9_-]+")
_DOT_LIKE: Final = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_MAX_LABEL_LENGTH: Final = 63
_MAX_HOST_LENGTH: Final = 253


class InvalidUrlError(ValueError):
    """Raised for any URL we refuse to process. ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    url: str
    scheme: str
    userinfo: str
    host: str  # lowercase ASCII (IDNA-encoded); IPs without brackets
    port: int | None  # None when absent or the scheme default
    path: str
    query: str
    fragment: str
    is_ip_host: bool
    scheme_inferred: bool


def _check_raw(raw: str, max_length: int) -> str:
    if len(raw) > max_length:
        raise InvalidUrlError("too_long", f"URL exceeds {max_length} characters")
    text = raw.strip()
    if not text:
        raise InvalidUrlError("empty", "URL is empty")
    if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in text):
        raise InvalidUrlError("illegal_char", "URL contains whitespace or control characters")
    return unicodedata.normalize("NFC", text)


def _ensure_scheme(text: str) -> tuple[str, bool]:
    """Return (text with a scheme, whether we had to infer it)."""
    if _SCHEME_RE.match(text):
        return text, False
    if text.startswith("//"):
        return "http:" + text, True
    if _OPAQUE_SCHEME_RE.match(text):
        raise InvalidUrlError("unsupported_scheme", "only http and https URLs are supported")
    return "http://" + text, True


def _split(text: str) -> SplitResult:
    try:
        return urlsplit(text)
    except ValueError as exc:
        raise InvalidUrlError("parse_error", "URL could not be parsed") from exc


def _port(parts: SplitResult) -> int | None:
    try:
        return parts.port
    except ValueError as exc:
        raise InvalidUrlError("bad_port", "URL has an invalid port") from exc


def _encode_label(label: str) -> str:
    if label.isascii():
        encoded = label
    else:
        try:
            encoded = idna.encode(label, uts46=True).decode("ascii")
        except Exception as exc:  # third-party codec: nothing may escape on hostile input
            raise InvalidUrlError("bad_idna", "hostname label is not valid IDNA") from exc
    if not encoded or len(encoded) > _MAX_LABEL_LENGTH or not _LABEL_RE.fullmatch(encoded):
        raise InvalidUrlError("bad_host", "hostname has an invalid label")
    return encoded


def _normalize_host(hostname: str) -> tuple[str, bool]:
    host = hostname.translate(_DOT_LIKE)
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise InvalidUrlError("no_host", "URL has no host")
    try:
        return str(ipaddress.ip_address(host)), True
    except ValueError:
        pass
    ascii_host = ".".join(_encode_label(label) for label in host.split("."))
    if len(ascii_host) > _MAX_HOST_LENGTH:
        raise InvalidUrlError("bad_host", "hostname is too long")
    return ascii_host, False


def _assemble(parts: NormalizedUrl) -> str:
    host = f"[{parts.host}]" if parts.is_ip_host and ":" in parts.host else parts.host
    auth = f"{parts.userinfo}@" if parts.userinfo else ""
    port = f":{parts.port}" if parts.port is not None else ""
    url = f"{parts.scheme}://{auth}{host}{port}{parts.path}"
    if parts.query:
        url += f"?{parts.query}"
    if parts.fragment:
        url += f"#{parts.fragment}"
    return url


def normalize_url(raw: str, *, max_length: int = DEFAULT_MAX_URL_LENGTH) -> NormalizedUrl:
    text, inferred = _ensure_scheme(_check_raw(raw, max_length))
    parts = _split(text)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise InvalidUrlError("unsupported_scheme", "only http and https URLs are supported")
    if parts.hostname is None:
        raise InvalidUrlError("no_host", "URL has no host")
    host, is_ip = _normalize_host(parts.hostname)
    port = _port(parts)
    draft = NormalizedUrl(
        url="",
        scheme=parts.scheme,
        userinfo=parts.netloc.rpartition("@")[0],
        host=host,
        port=None if port == _DEFAULT_PORTS.get(parts.scheme) else port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        is_ip_host=is_ip,
        scheme_inferred=inferred,
    )
    return replace(draft, url=_assemble(draft))
