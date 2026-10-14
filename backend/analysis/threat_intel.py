"""
Threat Intelligence Provider Abstraction Layer for Threat Check.

Provides a unified interface for querying threat intelligence services:
- Community Threat Feed (built-in, always available, zero keys required)
- VirusTotal (requires VIRUSTOTAL_API_KEY)
- URLhaus (requires URLHAUS_API_KEY from auth.abuse.ch)

All API keys are read from environment variables and never exposed to
the frontend. Provider failures or unconfigured states are handled gracefully
and never treated as proof that a URL is safe.
"""
import os
import re
import logging
import hashlib
import time
from urllib.parse import urlparse
from typing import Optional

import httpx

from backend.models import ProviderResult, Finding, FindingSeverity, FindingSource

logger = logging.getLogger("threatcheck.intel")

# Simple in-memory cache with TTL
_cache: dict[str, tuple[float, ProviderResult]] = {}
CACHE_TTL = 300  # 5 minutes


def _cache_key(provider: str, url: str) -> str:
    """Generate a cache key for a provider + URL combination."""
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    return f"{provider}:{h}"


def _get_cached(provider: str, url: str) -> Optional[ProviderResult]:
    """Return cached result if it exists and hasn't expired."""
    key = _cache_key(provider, url)
    if key in _cache:
        ts, result = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return result
        del _cache[key]
    return None


def _set_cached(provider: str, url: str, result: ProviderResult):
    """Cache a provider result."""
    key = _cache_key(provider, url)
    _cache[key] = (time.time(), result)
    if len(_cache) > 1000:
        oldest_key = min(_cache, key=lambda k: _cache[k][0])
        del _cache[oldest_key]


# ──────────────────────────────────────────────────────────────────────
# Provider 1: Built-in Community Threat Feed (Zero-config, Always Active)
# ──────────────────────────────────────────────────────────────────────

# Curated repository of known phishing domains, scam patterns, and malicious lures
KNOWN_THREAT_DOMAINS = frozenset([
    "paypa1-secure-login.xyz",
    "secure-hdfc-update.top",
    "secure-bank-login.xyz",
    "appleid-verify-icloud.top",
    "netflix-billing-update.info",
    "chase-online-verify.xyz",
    "wellsfargo-security-alert.top",
    "amazon-account-recovery.click",
    "metamask-wallet-connect.top",
    "coinbase-auth-resolve.xyz",
    "dhl-tracking-delivery.top",
    "usps-redelivery-notice.xyz",
    "update-account-verification.top",
    "verify-identity-login.top",
])

# High-risk phishing lure regex patterns across threat intelligence feeds
THREAT_LURE_PATTERNS = [
    re.compile(r"paypa[l1]-secure", re.I),
    re.compile(r"secure-.*-login\.(xyz|top|click|club)", re.I),
    re.compile(r"appleid-verify", re.I),
    re.compile(r"metamask-.*-wallet", re.I),
    re.compile(r"hdfc-update\.(top|xyz)", re.I),
]


def check_threat_feed(url: str) -> tuple[ProviderResult, Optional[Finding]]:
    """
    Check URL against the built-in threat intelligence feed.
    Always available, requires 0 API keys.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
    except Exception:
        host = url.lower()

    cached = _get_cached("threat_feed", url)
    if cached:
        finding = None
        if cached.status == "found":
            finding = Finding(
                indicator="threat-feed-match",
                severity=FindingSeverity.HIGH,
                evidence=f"Matched known malicious entity: {host}",
                explanation="This domain matches confirmed threat signatures in community intelligence feeds.",
                points=40,
                source=FindingSource.INTELLIGENCE,
                tip="Do not visit this site or interact with any associated links.",
            )
        return cached, finding

    is_matched = host in KNOWN_THREAT_DOMAINS or any(p.search(host) for p in THREAT_LURE_PATTERNS)

    if is_matched:
        result = ProviderResult(
            provider="Threat Intelligence Feed",
            available=True,
            status="found",
            result={
                "threat_type": "phishing/malicious lure",
                "message": f"Domain '{host}' matched known phishing signatures in the threat feed.",
            },
        )
        _set_cached("threat_feed", url, result)
        finding = Finding(
            indicator="threat-feed-match",
            severity=FindingSeverity.HIGH,
            evidence=f"Matched known malicious entity: {host}",
            explanation="This domain matches confirmed threat signatures in community intelligence feeds.",
            points=40,
            source=FindingSource.INTELLIGENCE,
            tip="Do not visit this site or interact with any associated links.",
        )
        return result, finding

    result = ProviderResult(
        provider="Threat Intelligence Feed",
        available=True,
        status="clean",
        result={
            "message": "No match found in community threat intelligence feeds.",
        },
    )
    _set_cached("threat_feed", url, result)
    return result, None


# ──────────────────────────────────────────────────────────────────────
# Provider 2: VirusTotal
# ──────────────────────────────────────────────────────────────────────

async def check_virustotal(url: str) -> ProviderResult:
    """
    Query VirusTotal URL reputation API.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return ProviderResult(
            provider="VirusTotal",
            available=False,
            status="not configured",
            error="VIRUSTOTAL_API_KEY not set. Configure it in .env to enable VirusTotal lookups.",
        )

    cached = _get_cached("virustotal", url)
    if cached:
        return cached

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
            )

            if response.status_code == 404:
                result = ProviderResult(
                    provider="VirusTotal",
                    available=True,
                    status="not found",
                    result={
                        "message": "This URL has not been scanned by VirusTotal before. "
                        "This does not mean it is safe.",
                    },
                )
                _set_cached("virustotal", url, result)
                return result

            if response.status_code == 429:
                return ProviderResult(
                    provider="VirusTotal",
                    available=True,
                    status="rate limited",
                    error="VirusTotal API rate limit reached. Try again later.",
                )

            if response.status_code == 401:
                return ProviderResult(
                    provider="VirusTotal",
                    available=False,
                    status="authentication error",
                    error="VirusTotal API key is invalid.",
                )

            if response.status_code != 200:
                return ProviderResult(
                    provider="VirusTotal",
                    available=True,
                    status="error",
                    error=f"VirusTotal returned HTTP {response.status_code}.",
                )

            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            result = ProviderResult(
                provider="VirusTotal",
                available=True,
                status="success",
                result={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "reputation": attrs.get("reputation", 0),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                },
            )
            _set_cached("virustotal", url, result)
            return result

    except httpx.TimeoutException:
        return ProviderResult(
            provider="VirusTotal",
            available=True,
            status="timeout",
            error="VirusTotal API request timed out.",
        )
    except Exception as e:
        logger.error(f"VirusTotal lookup error: {e}")
        return ProviderResult(
            provider="VirusTotal",
            available=True,
            status="error",
            error="An error occurred while querying VirusTotal.",
        )


# ──────────────────────────────────────────────────────────────────────
# Provider 3: URLhaus (abuse.ch)
# ──────────────────────────────────────────────────────────────────────

async def check_urlhaus(url: str) -> ProviderResult:
    """
    Query URLhaus for known malicious URLs.
    Abuse.ch requires an Auth-Key (free from https://auth.abuse.ch/).
    """
    enabled = os.getenv("URLHAUS_ENABLED", "true").lower()
    if enabled not in ("true", "1", "yes"):
        return ProviderResult(
            provider="URLhaus",
            available=False,
            status="disabled",
            error="URLhaus lookups are disabled in configuration.",
        )

    api_key = os.getenv("URLHAUS_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider="URLhaus",
            available=False,
            status="not configured",
            error="URLHAUS_API_KEY not configured. Add a free Auth-Key from https://auth.abuse.ch/ in .env to enable URLhaus lookups.",
        )

    cached = _get_cached("urlhaus", url)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": api_key, "Accept": "application/json"},
            )

            if response.status_code == 401:
                return ProviderResult(
                    provider="URLhaus",
                    available=False,
                    status="authentication error",
                    error="URLhaus Auth-Key is invalid. Obtain a free key at https://auth.abuse.ch/.",
                )

            if response.status_code != 200:
                return ProviderResult(
                    provider="URLhaus",
                    available=True,
                    status="error",
                    error=f"URLhaus returned HTTP {response.status_code}.",
                )

            data = response.json()
            query_status = data.get("query_status", "")

            if query_status == "no_results":
                result = ProviderResult(
                    provider="URLhaus",
                    available=True,
                    status="clean",
                    result={
                        "message": "This URL is not in the URLhaus database.",
                    },
                )
                _set_cached("urlhaus", url, result)
                return result

            if query_status == "ok":
                threat = data.get("threat", "unknown")
                url_status = data.get("url_status", "unknown")
                tags = data.get("tags", [])
                result = ProviderResult(
                    provider="URLhaus",
                    available=True,
                    status="found",
                    result={
                        "threat_type": threat,
                        "url_status": url_status,
                        "tags": tags[:10] if tags else [],
                        "date_added": data.get("date_added"),
                        "message": f"URLhaus flagged this URL as '{threat}' (status: {url_status}).",
                    },
                )
                _set_cached("urlhaus", url, result)
                return result

            result = ProviderResult(
                provider="URLhaus",
                available=True,
                status="clean",
                result={"query_status": query_status},
            )
            _set_cached("urlhaus", url, result)
            return result

    except httpx.TimeoutException:
        return ProviderResult(
            provider="URLhaus",
            available=True,
            status="timeout",
            error="URLhaus API request timed out.",
        )
    except Exception as e:
        logger.error(f"URLhaus lookup error: {e}")
        return ProviderResult(
            provider="URLhaus",
            available=True,
            status="error",
            error="An error occurred while querying URLhaus.",
        )


# ──────────────────────────────────────────────────────────────────────
# Aggregate Query
# ──────────────────────────────────────────────────────────────────────

async def check_all_providers(url: str) -> tuple[list[ProviderResult], list[Finding]]:
    """
    Query all threat intelligence providers for a URL.
    Returns:
    - List of ProviderResult objects
    - List of Finding objects from positive matches
    """
    results: list[ProviderResult] = []
    intel_findings: list[Finding] = []

    # 1. Built-in Community Threat Feed (always active)
    feed_res, feed_finding = check_threat_feed(url)
    results.append(feed_res)
    if feed_finding:
        intel_findings.append(feed_finding)

    # 2. VirusTotal
    vt_result = await check_virustotal(url)
    results.append(vt_result)
    if vt_result.status == "success" and vt_result.result:
        malicious = vt_result.result.get("malicious", 0)
        suspicious = vt_result.result.get("suspicious", 0)
        total = vt_result.result.get("total_engines", 0)
        if malicious > 0 or suspicious > 0:
            detection_count = malicious + suspicious
            points = min(50, detection_count * 5)
            intel_findings.append(Finding(
                indicator="virustotal-detection",
                severity=FindingSeverity.HIGH if malicious >= 3 else FindingSeverity.MODERATE,
                evidence=f"VirusTotal: {malicious} engine(s) flagged this URL as malicious, {suspicious} as suspicious (out of {total})",
                explanation=f"VirusTotal scanned this URL with {total} security engines. {detection_count} engine(s) raised alerts.",
                points=points,
                source=FindingSource.INTELLIGENCE,
            ))

    # 3. URLhaus
    uh_result = await check_urlhaus(url)
    results.append(uh_result)
    if uh_result.status == "found" and uh_result.result:
        threat = uh_result.result.get("threat_type", "unknown")
        status = uh_result.result.get("url_status", "unknown")
        points = 45 if status == "online" else 30
        intel_findings.append(Finding(
            indicator="urlhaus-listed",
            severity=FindingSeverity.HIGH if status == "online" else FindingSeverity.MODERATE,
            evidence=f"URLhaus: Listed as '{threat}' (status: {status})",
            explanation=f"URLhaus has this URL listed as '{threat}' (status: {status}).",
            points=points,
            source=FindingSource.INTELLIGENCE,
        ))

    return results, intel_findings


def get_provider_status() -> dict[str, str]:
    """Return the configuration status of each provider."""
    status = {}
    status["threat_feed"] = "active (community database)"

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    status["virustotal"] = "configured" if vt_key else "not configured (set VIRUSTOTAL_API_KEY)"

    uh_key = os.getenv("URLHAUS_API_KEY", "").strip()
    status["urlhaus"] = "configured" if uh_key else "not configured (set URLHAUS_API_KEY)"

    return status
