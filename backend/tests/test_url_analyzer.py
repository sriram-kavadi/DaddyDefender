"""
Unit tests for the URL Analyzer.

Covers URL parsing, suspicious indicators, brand impersonation,
scoring boundaries, and edge cases.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.analysis.url_analyzer import (
    analyze_url,
    parse_url,
    registrable_domain,
    levenshtein,
    lookalike_variants,
)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

LEVEL_ORDER = ["low", "moderate", "high", "critical"]


def level_for(score):
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def at_least(url, min_level):
    r = analyze_url(url)
    assert "error" not in r, f"Unexpected error for {url}: {r.get('error')}"
    actual = level_for(r["score"])
    assert LEVEL_ORDER.index(actual) >= LEVEL_ORDER.index(min_level), (
        f"Expected at least {min_level} but got {actual} (score={r['score']}) for: {url}"
    )


def at_most(url, max_level):
    r = analyze_url(url)
    assert "error" not in r, f"Unexpected error for {url}: {r.get('error')}"
    actual = level_for(r["score"])
    assert LEVEL_ORDER.index(actual) <= LEVEL_ORDER.index(max_level), (
        f"Expected at most {max_level} but got {actual} (score={r['score']}) for: {url}"
    )


def has_indicator(url, indicator):
    r = analyze_url(url)
    assert "error" not in r
    indicators = [f.indicator for f in r["findings"]]
    assert indicator in indicators, (
        f"Expected indicator '{indicator}' for: {url}\nGot: {indicators}"
    )


def lacks_indicator(url, indicator):
    r = analyze_url(url)
    assert "error" not in r
    indicators = [f.indicator for f in r["findings"]]
    assert indicator not in indicators, (
        f"Did not expect indicator '{indicator}' for: {url}"
    )


# ──────────────────────────────────────────────────────────────────────
# Helper function tests
# ──────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_levenshtein_basics(self):
        assert levenshtein("kitten", "sitting") == 3
        assert levenshtein("amazon", "amazom") == 1
        assert levenshtein("", "abc") == 3
        assert levenshtein("abc", "") == 3
        assert levenshtein("same", "same") == 0

    def test_registrable_domain(self):
        assert registrable_domain("www.example.com") == "example.com"
        assert registrable_domain("paypal.com.verify-account.xyz") == "verify-account.xyz"
        # tldextract handles co.uk properly
        result = registrable_domain("a.b.example.co.uk")
        assert "example" in result

    def test_lookalike_variants(self):
        variants = lookalike_variants("paypa1")
        assert "paypal" in variants  # 1 → l

    def test_parse_url_valid(self):
        r = parse_url("https://example.com")
        assert r is not None
        assert r["parsed"].hostname == "example.com"

    def test_parse_url_adds_scheme(self):
        r = parse_url("example.com/path")
        assert r is not None
        assert r["assumed_scheme"] is True

    def test_parse_url_invalid(self):
        r = parse_url("http://")
        assert r is None


# ──────────────────────────────────────────────────────────────────────
# Clean URLs (should be low risk)
# ──────────────────────────────────────────────────────────────────────

class TestCleanUrls:
    @pytest.mark.parametrize("url", [
        "https://www.paypal.com/signin",
        "https://github.com/anthropics",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.amazon.in/gp/help",
        "https://accounts.google.com/signin",
        "example.com",
        "https://pineapple.com/recipes",
        "https://www.bbc.co.uk/news",
    ])
    def test_clean_url_stays_low(self, url):
        at_most(url, "low")


# ──────────────────────────────────────────────────────────────────────
# Suspicious URL indicators
# ──────────────────────────────────────────────────────────────────────

class TestUrlIndicators:
    def test_http_is_minor_flag(self):
        has_indicator("http://example.com", "http")
        at_most("http://example.com", "low")

    def test_bare_domain_no_http_flag(self):
        lacks_indicator("example.com", "http")

    def test_ip_address_url(self):
        has_indicator("http://192.168.1.10/login", "ip")
        at_least("http://192.168.1.10/login", "moderate")

    def test_at_sign_trick(self):
        has_indicator("https://paypal.com@evil-site.xyz/login", "userinfo")
        at_least("https://paypal.com@evil-site.xyz/login", "moderate")

    def test_punycode_host(self):
        has_indicator("https://xn--pypal-4ve.com/login", "punycode")

    def test_shortener(self):
        has_indicator("https://bit.ly/3abcd", "shortener")

    def test_subdomain_brand_trick(self):
        has_indicator("https://paypal.com.verify-account.xyz/", "brand")
        at_least("https://paypal.com.verify-account.xyz/", "high")

    def test_digit_swap_lookalike(self):
        has_indicator("https://paypa1.com/login", "brand")
        at_least("https://paypa1.com/login", "moderate")

    def test_rn_for_m_lookalike(self):
        has_indicator("https://arnazon.com/deal", "brand")

    def test_zero_for_o_lookalike(self):
        has_indicator("https://micros0ft.com/", "brand")

    def test_one_letter_typo(self):
        has_indicator("https://amazom.com/", "brand")

    def test_brand_plus_keyword(self):
        at_least("http://paypa1-secure-login.xyz/verify?session=48213", "high")

    def test_brand_on_unknown_tld(self):
        has_indicator("https://netflix.top/billing", "brand")

    def test_risky_tld(self):
        has_indicator("https://random-shop.xyz", "tld")

    def test_many_subdomains(self):
        has_indicator("https://a.b.c.d.example.com", "subdomains")

    def test_unusual_port(self):
        has_indicator("https://example.com:8443/login", "port")

    def test_redirect_param(self):
        has_indicator("https://example.com/go?next=https://evil.xyz", "redirect-param")

    def test_executable_download(self):
        has_indicator("https://example.com/invoice.exe", "download")

    def test_javascript_scheme(self):
        r = analyze_url("javascript:alert(1)")
        actual = level_for(r["score"])
        assert actual == "high"
        assert r["findings"][0].indicator == "scheme"

    def test_data_scheme(self):
        has_indicator("data:text/html;base64,PHNjcmlwdD4=", "scheme")


# ──────────────────────────────────────────────────────────────────────
# Score boundaries
# ──────────────────────────────────────────────────────────────────────

class TestScoreBoundaries:
    def test_score_never_exceeds_100(self):
        r = analyze_url(
            "http://paypal.com.secure-login-verify-account.xyz:8080/login/verify/update.exe?u=https://x.xyz"
        )
        assert r["score"] <= 100
        assert r["score"] >= 75

    def test_empty_url_returns_error(self):
        r = analyze_url("")
        assert "error" in r

    def test_invalid_url_returns_error(self):
        r = analyze_url("http://")
        assert "error" in r


# ──────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_very_long_url(self):
        r = analyze_url("https://example.com/" + "a" * 500)
        assert "error" not in r
        assert r["score"] <= 100

    def test_heavily_encoded_url(self):
        r = analyze_url("https://example.com/%61%62%63%64%65%66%67%68%69%6A")
        has_indicator("https://example.com/%61%62%63%64%65%66%67%68%69%6A", "encoded")

    def test_url_with_unusual_port(self):
        r = analyze_url("https://example.com:9999/")
        assert "error" not in r

    def test_ftp_scheme(self):
        r = analyze_url("ftp://files.example.com/doc.pdf")
        assert "error" not in r
        indicators = [f.indicator for f in r["findings"]]
        assert "scheme" in indicators

    def test_localhost(self):
        r = analyze_url("http://localhost:3000")
        assert "error" not in r
