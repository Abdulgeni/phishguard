"""Unit tests for app.services.email_extractor."""

import pytest

from app.services.email_extractor import extract_urls, host_of


def test_extracts_http_and_https() -> None:
    body = "Visit http://a.com/login or https://b.com/verify now."
    urls, truncated = extract_urls(body, max_urls=20)
    assert urls == ["http://a.com/login", "https://b.com/verify"]
    assert truncated is False


def test_extracts_www_without_scheme() -> None:
    body = "Check www.example.com and www.foo.co.uk/page"
    urls, _ = extract_urls(body, max_urls=20)
    assert urls == ["http://www.example.com", "http://www.foo.co.uk/page"]


def test_deduplicates_by_normalized_form() -> None:
    body = "http://example.com/ and http://example.com"
    urls, _ = extract_urls(body, max_urls=20)
    assert urls == ["http://example.com/"]


def test_truncates_and_flags() -> None:
    body = " ".join(f"http://example{i}.com/" for i in range(30))
    urls, truncated = extract_urls(body, max_urls=5)
    assert len(urls) == 5
    assert truncated is True


def test_returns_empty_for_no_urls() -> None:
    urls, truncated = extract_urls("hello world, no links here", max_urls=20)
    assert urls == []
    assert truncated is False


def test_drops_invalid_candidates() -> None:
    body = "http:// http://a b.com/ http://good.com/x"
    urls, _ = extract_urls(body, max_urls=20)
    # Only the last one survives; the first two fail normalization.
    assert "http://good.com/x" in urls


def test_ignores_bare_domains() -> None:
    # No scheme, no www => we do not extract (filenames, plain text, etc.).
    body = "report.pdf is at example.com but that's not a link"
    urls, _ = extract_urls(body, max_urls=20)
    assert urls == []


def test_rejects_non_positive_max_urls() -> None:
    with pytest.raises(ValueError, match="max_urls"):
        extract_urls("http://a.com/", max_urls=0)


def test_host_of_handles_garbage() -> None:
    assert host_of("http://example.com/x") == "example.com"
    assert host_of("not a url") == ""
    assert host_of("") == ""


def test_urls_inside_punctuation_are_trimmed() -> None:
    body = "See (http://example.com/login), then [http://other.com/verify]."
    urls, _ = extract_urls(body, max_urls=20)
    assert urls == ["http://example.com/login", "http://other.com/verify"]
