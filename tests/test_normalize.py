import random

import pytest

from app.features.normalize import InvalidUrlError, NormalizedUrl, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "http://example.com"),
        ("//example.com/x", "http://example.com/x"),
        ("HTTPS://WWW.Example.COM/Path?Q=1#Frag", "https://www.example.com/Path?Q=1#Frag"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        ("example.com:8080/login", "http://example.com:8080/login"),
        ("http://example.com./x", "http://example.com/x"),
        ("  http://example.com/x \n", "http://example.com/x"),
        ("http://example.com/?", "http://example.com/"),
        ("http://my_host.example.com/", "http://my_host.example.com/"),
        ("http://xn--pypal-4ve.com/login", "http://xn--pypal-4ve.com/login"),
        ("http://bücher.example.com/shop", "http://xn--bcher-kva.example.com/shop"),
        ("http://bu\u0308cher.example.com/shop", "http://xn--bcher-kva.example.com/shop"),
        ("http://example\u3002com/", "http://example.com/"),
        ("http://[2001:DB8::1]/login", "http://[2001:db8::1]/login"),
        ("http://192.0.2.1/a", "http://192.0.2.1/a"),
        ("http://a.com/%41%2e", "http://a.com/%41%2e"),
    ],
)
def test_normalizes(raw: str, expected: str) -> None:
    assert normalize_url(raw).url == expected


def test_fields_are_exposed() -> None:
    n = normalize_url("http://user:pw@Evil.example.com:8080/a/b?x=1&y=2#top")
    assert (n.scheme, n.userinfo, n.host, n.port) == ("http", "user:pw", "evil.example.com", 8080)
    assert (n.path, n.query, n.fragment) == ("/a/b", "x=1&y=2", "top")
    assert n.url == "http://user:pw@evil.example.com:8080/a/b?x=1&y=2#top"
    assert n.is_ip_host is False
    assert n.scheme_inferred is False


def test_deceptive_userinfo_keeps_the_real_host() -> None:
    n = normalize_url("http://paypal.com@evil.com/login")
    assert n.host == "evil.com"
    assert n.userinfo == "paypal.com"


def test_ip_hosts_are_flagged() -> None:
    assert normalize_url("http://192.0.2.1/a").is_ip_host is True
    assert normalize_url("http://[2001:db8::1]/x").is_ip_host is True
    assert normalize_url("http://1.2.3.example.com/").is_ip_host is False


def test_scheme_inferred_flag() -> None:
    assert normalize_url("example.com").scheme_inferred is True
    assert normalize_url("http://example.com").scheme_inferred is False


def test_length_cap_boundaries() -> None:
    prefix = "http://a.com/"
    assert normalize_url(prefix + "x" * (2048 - len(prefix))).path.startswith("/xxx")
    with pytest.raises(InvalidUrlError) as err:
        normalize_url(prefix + "x" * (2049 - len(prefix)))
    assert err.value.reason == "too_long"
    with pytest.raises(InvalidUrlError):
        normalize_url("http://example.com/abcdef", max_length=20)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("http://", "no_host"),
        ("http://./", "no_host"),
        ("http://:80/", "no_host"),
        ("ftp://files.example.org/a", "unsupported_scheme"),
        ("javascript:alert(1)", "unsupported_scheme"),
        ("mailto:a@b.com", "unsupported_scheme"),
        ("http://a b.com/", "illegal_char"),
        ("http://a.com/\x00", "illegal_char"),
        ("http://a.com/\tb", "illegal_char"),
        ("http://a..com/", "bad_host"),
        ("http://exa$mple.com/", "bad_host"),
        ("http://" + "a" * 64 + ".com/", "bad_host"),
        ("http://" + ".".join(["a" * 60] * 5) + "/", "bad_host"),
        ("http://[::1/", "parse_error"),
        ("http://a.com:99999/", "bad_port"),
        ("http://a.com:abc/", "bad_port"),
        ("http://\u202eevil.com/", "bad_idna"),
        ("http://\ud800.com/", "bad_idna"),
    ],
)
def test_rejects_with_reason(raw: str, reason: str) -> None:
    with pytest.raises(InvalidUrlError) as err:
        normalize_url(raw)
    assert err.value.reason == reason
    assert err.value.detail


_ALPHABET = "ahttp:/.@[]%#?&=-_ 0123456789ü。\u202e\x00\ud800"
_PREFIXES = ["", "http://", "https://a.", "//"]


def test_never_raises_anything_but_invalid_url_error_and_is_idempotent() -> None:
    rng = random.Random(42)
    accepted = 0
    for _ in range(5000):
        body = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 60)))
        raw = rng.choice(_PREFIXES) + body
        try:
            result = normalize_url(raw)
        except InvalidUrlError:
            continue
        accepted += 1
        assert isinstance(result, NormalizedUrl)
        assert normalize_url(result.url).url == result.url
    assert accepted > 0
