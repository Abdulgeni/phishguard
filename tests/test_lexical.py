import random
import socket
from typing import Any

import pytest

from app.features import lexical
from app.features.lexical import (
    LEXICAL_FEATURE_NAMES,
    extract_lexical,
    load_suspicious_keywords,
)
from app.features.normalize import InvalidUrlError, normalize_url

EXPECTED_NAMES = (
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


def feats(raw: str) -> dict[str, int]:
    return extract_lexical(normalize_url(raw))


def golden(*values: int) -> dict[str, int]:
    return dict(zip(EXPECTED_NAMES, values, strict=True))


def test_feature_names_match_the_frozen_contract() -> None:
    assert LEXICAL_FEATURE_NAMES == EXPECTED_NAMES
    assert len(set(EXPECTED_NAMES)) == 17


def test_output_is_ordered_plain_ints() -> None:
    out = feats("http://www.example.com/a")
    assert tuple(out) == EXPECTED_NAMES
    assert all(type(v) is int for v in out.values())


def test_golden_plain_url() -> None:
    # http://www.example.com/a/b?x=1&y=2
    assert feats("http://www.example.com/a/b?x=1&y=2") == golden(
        34, 15, 4, 2, 0, 2, 4, 2, 1, 0, 0, 0, 3, 2, 0, 0, 0
    )


def test_golden_ip_host() -> None:
    # http://192.0.2.77/login/verify.php
    assert feats("http://192.0.2.77/login/verify.php") == golden(
        34, 10, 17, 4, 0, 7, 4, 0, -1, 1, 0, 0, -1, 2, 2, 0, 0
    )


def test_golden_everything_at_once() -> None:
    # https://secure.paypa1-login.example.co.uk/a//b%2Fc?u=me@x.com&&p=%7E#frag
    raw = "https://secure.paypa1-login.example.co.uk/a//b%2Fc?u=me@x.com&&p=%7E#frag"
    assert feats(raw) == golden(73, 33, 9, 5, 1, 3, 5, 2, 2, 0, 1, 0, 5, 2, 2, 1, 1)


@pytest.mark.parametrize(
    ("raw", "feature", "expected"),
    [
        ("http://a.com/?a=1&b", "num_query_params", 2),
        ("http://a.com/?&&", "num_query_params", 0),
        ("http://a.com/", "num_query_params", 0),
        ("http://a.com", "path_depth", 0),
        ("http://a.com/", "path_depth", 0),
        ("http://a.com/a/b/", "path_depth", 2),
        ("http://a.com/a//b", "path_depth", 2),
        ("http://a1b2.com/3", "num_digits", 3),
        ("http://my-site.example.com/a-b", "num_hyphens", 2),
        ("http://a.b.c.example.com", "num_subdomains", 3),
        ("http://example.com", "num_subdomains", 0),
        ("http://www.example.co.uk", "num_subdomains", 1),
        ("http://example.com", "tld_length", 3),
        ("http://example.co.uk", "tld_length", 5),
        ("http://paypal.com@evil.com/login", "has_at_symbol", 1),
        ("http://a.com/x", "has_at_symbol", 0),
        ("http://xn--pypal-4ve.com/login", "has_punycode", 1),
        ("http://bücher.example.com/", "has_punycode", 1),
        ("http://axn--b.com/", "has_punycode", 0),
        ("http://a.com//x", "has_double_slash_in_path", 1),
        ("http://a.com/x?r=http://b.com", "has_double_slash_in_path", 0),
        ("http://a.com/a/b", "has_double_slash_in_path", 0),
        ("http://a.com/%2e", "has_hex_encoding", 1),
        ("http://a.com/%2E?x=%41", "has_hex_encoding", 1),
        ("http://a.com/%zz", "has_hex_encoding", 0),
        ("http://a.com/50%", "has_hex_encoding", 0),
        ("http://192.0.2.1/", "has_ip_host", 1),
        ("http://1.2.3.example.com/", "has_ip_host", 0),
        ("http://[2001:db8::1]/login", "host_length", 11),
        ("http://[2001:db8::1]/login", "has_ip_host", 1),
        ("http://[2001:db8::1]/login", "num_subdomains", -1),
        ("http://[2001:db8::1]/login", "tld_length", -1),
        ("http://localhost/admin", "has_ip_host", 0),
        ("http://localhost/admin", "num_subdomains", -1),
        ("http://localhost/admin", "tld_length", -1),
    ],
)
def test_single_feature(raw: str, feature: str, expected: int) -> None:
    assert feats(raw)[feature] == expected


@pytest.mark.parametrize(
    ("raw", "hits"),
    [
        ("http://a.com/login/login/login", 1),
        ("http://a.com/LOGIN", 1),
        ("http://a.com/Verify-Account", 2),
        ("http://login.secure-bank.com/", 3),
        ("http://a.com/#login", 1),
        ("http://a.com/news", 0),
    ],
)
def test_keyword_hits_are_distinct_and_case_insensitive(raw: str, hits: int) -> None:
    assert feats(raw)["suspicious_keyword_hits"] == hits


def test_keyword_list_is_clean() -> None:
    words = load_suspicious_keywords()
    assert len(words) >= 20
    assert all(word and word == word.strip().lower() for word in words)
    assert len(set(words)) == len(words)
    for a in words:
        for b in words:
            if a != b:
                assert a not in b, f"{a!r} is a substring of {b!r}"


def test_no_network_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features import suffix

    suffix.extractor.cache_clear()

    def blocked(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    assert feats("http://a.b.example.co.uk/")["tld_length"] == 5
    suffix.extractor.cache_clear()


def test_extractor_failure_degrades_to_sentinels(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_host: str) -> None:
        raise RuntimeError("public suffix parser exploded")

    monkeypatch.setattr(lexical, "extractor", lambda: boom)
    out = feats("http://www.example.com/x")
    assert out["num_subdomains"] == -1
    assert out["tld_length"] == -1
    assert tuple(out) == EXPECTED_NAMES


_ALPHABET = "ahttp:/.@[]%#?&=-_ 0123456789ü。\u202e\x00\ud800"
_PREFIXES = ["", "http://", "https://a.", "//"]


def test_fuzz_never_raises_and_keeps_contract() -> None:
    rng = random.Random(42)
    checked = 0
    for _ in range(2000):
        body = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 60)))
        try:
            url = normalize_url(rng.choice(_PREFIXES) + body)
        except InvalidUrlError:
            continue
        out = extract_lexical(url)
        assert tuple(out) == EXPECTED_NAMES
        assert all(type(v) is int for v in out.values())
        checked += 1
    assert checked > 0
