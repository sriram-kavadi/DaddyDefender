"""
Unit tests for the Message Analyzer.

Covers message pattern detection, link extraction, brand mismatch,
negation handling, and scoring.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.analysis.message_analyzer import analyze_message, extract_urls


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


def at_least(text, min_level):
    r = analyze_message(text)
    actual = level_for(r["score"])
    assert LEVEL_ORDER.index(actual) >= LEVEL_ORDER.index(min_level), (
        f"Expected at least {min_level} but got {actual} (score={r['score']}) for message"
    )


def at_most(text, max_level):
    r = analyze_message(text)
    actual = level_for(r["score"])
    assert LEVEL_ORDER.index(actual) <= LEVEL_ORDER.index(max_level), (
        f"Expected at most {max_level} but got {actual} (score={r['score']}) for message"
    )


def has_indicator(text, indicator):
    r = analyze_message(text)
    all_indicators = [f.indicator for f in r["findings"]]
    for link in r["links"]:
        all_indicators.extend(f.indicator for f in link.findings)
    assert indicator in all_indicators, (
        f"Expected indicator '{indicator}'\nGot: {all_indicators}"
    )


def lacks_indicator(text, indicator):
    r = analyze_message(text)
    all_indicators = [f.indicator for f in r["findings"]]
    for link in r["links"]:
        all_indicators.extend(f.indicator for f in link.findings)
    assert indicator not in all_indicators, (
        f"Did not expect indicator '{indicator}'"
    )


# ──────────────────────────────────────────────────────────────────────
# Link extraction
# ──────────────────────────────────────────────────────────────────────

class TestLinkExtraction:
    def test_explicit_url(self):
        urls = extract_urls("Visit https://example.com/page for more info")
        assert "https://example.com/page" in urls

    def test_bare_domain(self):
        urls = extract_urls("Check out paypa1-secure.com/verify")
        assert any("paypa1-secure.com" in u for u in urls)

    def test_email_not_url(self):
        urls = extract_urls("write to support@paypal.com please")
        assert len(urls) == 0

    def test_trailing_punctuation_stripped(self):
        urls = extract_urls("Visit http://example.com/x).")
        assert urls[0] == "http://example.com/x"

    def test_file_names_not_links(self):
        urls = extract_urls("see report.pdf and notes.txt")
        assert len(urls) == 0

    def test_multiple_urls(self):
        urls = extract_urls("Visit bit.ly/abc and http://192.168.0.1/x")
        assert len(urls) == 2

    def test_deduplication(self):
        urls = extract_urls("Visit https://example.com and https://example.com again")
        assert len(urls) == 1


# ──────────────────────────────────────────────────────────────────────
# Phishing message detection
# ──────────────────────────────────────────────────────────────────────

PHISHING_MSG = (
    "URGENT: Your bank account has been suspended due to unusual activity. "
    "Verify your identity within 24 hours or your account will be closed. "
    "Click here: http://secure-hdfc-update.top/login and enter your OTP and card number. "
    "Do not tell anyone."
)

class TestPhishingDetection:
    def test_obvious_phishing_is_high_or_critical(self):
        at_least(PHISHING_MSG, "high")

    def test_phishing_has_multiple_indicators(self):
        r = analyze_message(PHISHING_MSG)
        ids = [f.indicator for f in r["findings"]]
        for expected in ["urgency", "threat", "credentials", "click", "secrecy", "combo"]:
            assert expected in ids, f"Missing indicator: {expected}"

    def test_prize_scam(self):
        at_least(
            "Congratulations, you have won a cash prize! Claim your prize now by paying "
            "a small fee in gift cards. Dear customer, act now!!!",
            "high",
        )

    def test_courier_fee_scam(self):
        at_least(
            "Your parcel is on hold. Pay the delivery fee at https://post-track.top/pay within 24 hours",
            "high",
        )

    def test_brand_mismatch(self):
        has_indicator(
            "Your PayPal account needs attention: https://account-check.example.xyz/login",
            "brand-mismatch",
        )


# ──────────────────────────────────────────────────────────────────────
# Benign messages (should be low risk)
# ──────────────────────────────────────────────────────────────────────

class TestBenignMessages:
    def test_harmless_meeting_message(self):
        at_most(
            "Hi, the meeting notes are at https://docs.example.org/notes. See you at 3.",
            "low",
        )

    def test_plain_chat(self):
        at_most("Are we still on for lunch tomorrow? I can do 1pm.", "low")

    def test_security_advice_not_flagged(self):
        text = "Never share your OTP with anyone. Our staff will not ask for your password."
        lacks_indicator(text, "credentials")
        at_most(text, "low")


# ──────────────────────────────────────────────────────────────────────
# Link analysis within messages
# ──────────────────────────────────────────────────────────────────────

class TestLinksInMessages:
    def test_links_analyzed_separately(self):
        r = analyze_message("Look at bit.ly/abc and http://192.168.0.1/x")
        assert len(r["links"]) == 2

    def test_max_links_cap(self):
        many = " ".join(f"https://site{i}.example.com" for i in range(25))
        r = analyze_message(many)
        assert len(r["links"]) <= 10


# ──────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_very_long_input(self):
        r = analyze_message("urgent " * 5000)
        assert r["score"] <= 100

    def test_html_in_input(self):
        r = analyze_message("<img src=x onerror=alert(1)> verify your account urgently")
        assert len(r["findings"]) > 0

    def test_empty_message(self):
        r = analyze_message("")
        assert r["score"] == 0

    def test_shouting_detection(self):
        r = analyze_message("ACT NOW OR YOUR ACCOUNT WILL BE DELETED IMMEDIATELY!!!")
        indicators = [f.indicator for f in r["findings"]]
        assert "shouting" in indicators

    def test_remote_access_scam(self):
        has_indicator(
            "Our tech support needs you to install AnyDesk to fix your computer",
            "remote",
        )

    def test_callback_scam(self):
        has_indicator(
            "Call our support at +1 800 555 1234 to claim your refund",
            "callback",
        )
