"""
Unified Threat Assessment and Scoring Engine for Threat Check.

Provides a centralized scoring system shared by URL and message analysis.
Assigns evidence-based risk scores, classifies threats, generates
explanations, and produces safety recommendations.

Scoring rules:
- 0-24: Low risk
- 25-49: Moderate risk
- 50-74: High risk
- 75-100: Critical risk

The engine avoids double-counting the same signal and distinguishes
weak heuristic evidence from verified reputation data.
"""
import os
import re
import logging
from typing import Optional

logger = logging.getLogger("threatcheck.scoring")
from backend.models import (
    Finding,
    FindingSeverity,
    FindingSource,
    RiskLevel,
    Classification,
    LinkAnalysis,
    ScanType,
)


# ──────────────────────────────────────────────────────────────────────
# Level / classification mapping
# ──────────────────────────────────────────────────────────────────────

LEVEL_LABELS = {
    RiskLevel.LOW: "Low risk",
    RiskLevel.MODERATE: "Moderate risk",
    RiskLevel.HIGH: "High risk",
    RiskLevel.CRITICAL: "Critical risk",
}

LEVEL_SUMMARIES = {
    RiskLevel.LOW: "No strong warning signs were found. This does not prove the link or message is safe.",
    RiskLevel.MODERATE: "Some warning signs were found. Treat this with caution and verify it through an official channel.",
    RiskLevel.HIGH: "Several warning signs were found that match common phishing and scam patterns.",
    RiskLevel.CRITICAL: "This is a strong match for phishing or scam patterns. Do not interact with it.",
}

BASE_RECOMMENDATIONS = {
    RiskLevel.LOW: [
        "Even with a low rating, avoid entering passwords or payment details unless you reached the site by typing its address yourself.",
    ],
    RiskLevel.MODERATE: [
        "Do not use the link or phone number in the message. Open the organization's official site by typing its address, or use a bookmark you saved earlier.",
        "Contact the sender through an address or number you already trust and ask whether they sent it.",
    ],
    RiskLevel.HIGH: [
        "Do not click the link, open attachments, or reply.",
        "Do not enter passwords, one-time codes, or card details.",
        "Report it as phishing in your email or messaging app, then delete it.",
    ],
    RiskLevel.CRITICAL: [
        "Do not click the link, open attachments, or reply.",
        "Do not enter passwords, one-time codes, or card details.",
        "Report it as phishing in your email or messaging app, then delete it.",
        "If you already clicked or shared details, change the affected passwords now and contact your bank or the service provider.",
    ],
}

LIMITATIONS_TEXT = (
    "This analysis examines the text and URL structure you submitted. "
    "It cannot determine domain age, certificate validity, redirect destinations, "
    "or whether the address appears on all blocklists. Reputation checks are limited "
    "to configured threat intelligence providers. Treat the result as a second opinion. "
    "When in doubt, contact the organization using details you already trust."
)

# Indicators that strongly suggest specific classifications
PHISHING_INDICATORS = frozenset(["credentials", "brand", "brand-mismatch", "combo"])
SCAM_INDICATORS = frozenset(["prize", "payment", "remote"])
FRAUD_INDICATORS = frozenset(["authority", "callback"])


# ──────────────────────────────────────────────────────────────────────
# Scoring
# ──────────────────────────────────────────────────────────────────────

def level_for(score: int) -> RiskLevel:
    """Map a numeric score to a risk level."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def classify_threat(
    scan_type: ScanType,
    score: int,
    findings: list[Finding],
    links: list[LinkAnalysis],
) -> str:
    """
    Determine a threat classification based on the evidence.

    Returns one of:
    - "no significant threat detected"
    - "suspicious"
    - "potentially fraudulent"
    - "phishing"
    - "scam"
    - "inconclusive"
    """
    all_indicators = {f.indicator for f in findings}
    # Include link findings too
    for link in links:
        for f in link.findings:
            all_indicators.add(f.indicator)

    level = level_for(score)

    if level == RiskLevel.LOW:
        if len(findings) == 0 and all(l.risk_score == 0 for l in links):
            return Classification.SAFE.value
        return Classification.SAFE.value

    # Check for phishing indicators
    has_phishing = bool(all_indicators & PHISHING_INDICATORS)
    has_scam = bool(all_indicators & SCAM_INDICATORS)
    has_fraud = bool(all_indicators & FRAUD_INDICATORS)

    if level == RiskLevel.CRITICAL:
        if has_phishing:
            return Classification.PHISHING.value
        if has_scam:
            return Classification.SCAM.value
        return Classification.PHISHING.value  # default for critical

    if level == RiskLevel.HIGH:
        if has_phishing:
            return Classification.PHISHING.value
        if has_scam:
            return Classification.SCAM.value
        if has_fraud:
            return Classification.POTENTIALLY_FRAUDULENT.value
        return Classification.SUSPICIOUS.value

    if level == RiskLevel.MODERATE:
        if has_phishing or has_scam:
            return Classification.SUSPICIOUS.value
        if has_fraud:
            return Classification.POTENTIALLY_FRAUDULENT.value
        return Classification.SUSPICIOUS.value

    return Classification.INCONCLUSIVE.value


def confidence_description(score: int, findings: list[Finding], provider_count: int) -> str:
    """
    Describe the strength of the evidence behind the risk assessment.
    """
    heuristic_count = sum(1 for f in findings if f.source == FindingSource.HEURISTIC)
    intel_count = sum(1 for f in findings if f.source == FindingSource.INTELLIGENCE)

    parts = []

    if heuristic_count == 0 and intel_count == 0:
        return "No indicators were matched. This assessment is based on the absence of known warning signs."

    if intel_count > 0:
        parts.append(f"{intel_count} threat intelligence indicator(s)")
    if heuristic_count > 0:
        parts.append(f"{heuristic_count} heuristic rule(s)")

    base = f"Based on {' and '.join(parts)}."

    if provider_count > 0 and intel_count > 0:
        base += " Includes data from external threat intelligence providers."
    elif provider_count == 0:
        base += " No external reputation services were consulted."

    if score < 25:
        base += " Evidence is limited; a low score does not guarantee safety."
    elif score >= 75:
        base += " Multiple strong indicators are present."

    return base


def generate_recommendations(
    level: RiskLevel,
    findings: list[Finding],
    links: list[LinkAnalysis],
) -> list[str]:
    """
    Generate safety recommendations based on the risk level and findings.
    Combines base recommendations with finding-specific tips.
    """
    recs = list(BASE_RECOMMENDATIONS.get(level, []))

    # Add unique tips from findings
    all_findings = list(findings)
    for link in links:
        all_findings.extend(link.findings)

    for f in all_findings:
        if f.tip and f.tip not in recs:
            recs.append(f.tip)

    return recs[:7]  # Cap at 7 recommendations


def generate_explanation(
    scan_type: ScanType,
    score: int,
    level: RiskLevel,
    classification: str,
    findings: list[Finding],
    links: list[LinkAnalysis],
) -> str:
    """
    Generate a template-based human-readable explanation.
    Used as a fallback when no AI provider is configured.
    """
    summary = LEVEL_SUMMARIES.get(level, "")

    if not findings and not links:
        if scan_type == ScanType.URL:
            return f"{summary} None of the URL analysis rules matched."
        return f"{summary} None of the message analysis rules matched."

    finding_count = len(findings)
    link_count = len(links)

    parts = [summary]

    if finding_count > 0:
        top = findings[:3]
        details = "; ".join(f.evidence for f in top)
        parts.append(f"Key findings: {details}.")

    if link_count > 0:
        risky = [l for l in links if l.risk_score >= 25]
        if risky:
            parts.append(
                f"{len(risky)} of {link_count} link(s) in the message show warning signs."
            )

    return " ".join(parts)


async def generate_ai_explanation(
    scan_type: ScanType,
    score: int,
    level: RiskLevel,
    classification: str,
    findings: list[Finding],
    links: list[LinkAnalysis],
    input_text: str = "",
) -> str:
    """
    Generate an AI-powered natural language explanation using Gemini if configured,
    falling back to the deterministic template-based explanation on error or missing key.
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        return generate_explanation(scan_type, score, level, classification, findings, links)

    prompt = (
        f"You are a cybersecurity expert assistant for Threat Check. "
        f"A user submitted a {scan_type.value}. Threat Assessment: Risk Score {score}/100, Level: {level.value.upper()}, Classification: {classification}. "
        f"Indicators detected: {'; '.join(f.evidence for f in findings) if findings else 'None'}. "
        f"Write a concise, plain English 2-sentence explanation for the user explaining why this rating was given and whether they should interact with it. Do not use markdown headers or bullet points."
    )

    try:
        import httpx
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and parts[0].get("text"):
                        ai_text = parts[0]["text"].strip()
                        if ai_text:
                            return ai_text
    except Exception as e:
        logger.warning(f"Gemini explanation generation skipped/failed: {e}")

    return generate_explanation(scan_type, score, level, classification, findings, links)


def detect_type(text: str) -> ScanType:
    """
    Determine whether the input is a URL or a message.
    Single tokens that look like URLs → url; everything else → message.
    """
    t = text.strip()
    if re.search(r"\s", t):
        return ScanType.MESSAGE
    if re.match(r"^[a-z][a-z0-9+.\-]*://", t, re.IGNORECASE):
        return ScanType.URL
    if re.match(r"^(javascript|data|vbscript):", t, re.IGNORECASE):
        return ScanType.URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}([/:?#]|$)", t):
        return ScanType.URL
    if re.match(r"^[^\s/@]+\.[a-z]{2,24}([/:?#]|$)", t, re.IGNORECASE):
        return ScanType.URL
    return ScanType.MESSAGE
