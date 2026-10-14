"""
Unit tests for Threat Intelligence Provider Abstraction.

Tests in-memory caching, provider status reporting, community threat feed,
unconfigured fallbacks, and disabled provider behavior.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.analysis.threat_intel import (
    _cache_key,
    _get_cached,
    _set_cached,
    check_threat_feed,
    check_virustotal,
    check_urlhaus,
    get_provider_status,
    check_all_providers,
)
from backend.models import ProviderResult


class TestCaching:
    def test_cache_set_and_get(self):
        url = "https://example.com/test-cache"
        res = ProviderResult(provider="TestProvider", available=True, status="success")
        _set_cached("test", url, res)
        cached = _get_cached("test", url)
        assert cached is not None
        assert cached.provider == "TestProvider"
        assert cached.status == "success"

    def test_cache_miss(self):
        cached = _get_cached("test", "https://nonexistent-url-xyz.com")
        assert cached is None


class TestCommunityThreatFeed:
    def test_clean_url(self):
        result, finding = check_threat_feed("https://github.com")
        assert result.provider == "Threat Intelligence Feed"
        assert result.available is True
        assert result.status == "clean"
        assert finding is None

    def test_known_phishing_domain(self):
        result, finding = check_threat_feed("http://paypa1-secure-login.xyz/verify")
        assert result.provider == "Threat Intelligence Feed"
        assert result.available is True
        assert result.status == "found"
        assert finding is not None
        assert finding.points >= 30


class TestVirusTotalProvider:
    @pytest.mark.asyncio
    async def test_virustotal_not_configured(self):
        old_val = os.environ.pop("VIRUSTOTAL_API_KEY", None)
        try:
            result = await check_virustotal("https://example.com")
            assert result.provider == "VirusTotal"
            assert result.available is False
            assert "not configured" in result.status
        finally:
            if old_val:
                os.environ["VIRUSTOTAL_API_KEY"] = old_val


class TestUrlhausProvider:
    @pytest.mark.asyncio
    async def test_urlhaus_not_configured(self):
        old_val = os.environ.pop("URLHAUS_API_KEY", None)
        try:
            result = await check_urlhaus("https://example.com")
            assert result.provider == "URLhaus"
            assert result.available is False
            assert "not configured" in result.status
        finally:
            if old_val:
                os.environ["URLHAUS_API_KEY"] = old_val

    @pytest.mark.asyncio
    async def test_urlhaus_disabled(self):
        old_val = os.environ.get("URLHAUS_ENABLED")
        os.environ["URLHAUS_ENABLED"] = "false"
        try:
            result = await check_urlhaus("https://example.com")
            assert result.provider == "URLhaus"
            assert result.available is False
            assert result.status == "disabled"
        finally:
            if old_val:
                os.environ["URLHAUS_ENABLED"] = old_val
            else:
                os.environ.pop("URLHAUS_ENABLED", None)


class TestProviderStatus:
    def test_provider_status(self):
        status = get_provider_status()
        assert "threat_feed" in status
        assert "virustotal" in status
        assert "urlhaus" in status
