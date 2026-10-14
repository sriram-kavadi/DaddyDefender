"""
Unit tests for the Scoring Engine.

Tests risk level assignment, classification logic, recommendation generation,
explanation generation, and confidence calculations.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.models import (
    Finding,
    FindingSeverity,
    FindingSource,
    RiskLevel,
    Classification,
    ScanType,
    LinkAnalysis,
)
from backend.analysis.scoring import (
    level_for,
    classify_threat,
    confidence_description,
    generate_recommendations,
    generate_explanation,
    LIMITATIONS_TEXT,
)


def _make_finding(indicator="urgent", points=15, severity=FindingSeverity.MODERATE, evidence="hurry up"):
    return Finding(
        indicator=indicator,
        severity=severity,
        evidence=evidence,
        explanation="Urgency is a common phishing sign",
        points=points,
        source=FindingSource.HEURISTIC,
    )


class TestLevelFor:
    def test_low_risk(self):
        assert level_for(0) == RiskLevel.LOW
        assert level_for(24) == RiskLevel.LOW

    def test_moderate_risk(self):
        assert level_for(25) == RiskLevel.MODERATE
        assert level_for(49) == RiskLevel.MODERATE

    def test_high_risk(self):
        assert level_for(50) == RiskLevel.HIGH
        assert level_for(74) == RiskLevel.HIGH

    def test_critical_risk(self):
        assert level_for(75) == RiskLevel.CRITICAL
        assert level_for(100) == RiskLevel.CRITICAL


class TestClassifyThreat:
    def test_safe_classification(self):
        result = classify_threat(ScanType.URL, 0, [], [])
        assert result == Classification.SAFE.value

    def test_suspicious_classification(self):
        result = classify_threat(ScanType.URL, 30, [_make_finding("suspicious-tld", 20)], [])
        assert result == Classification.SUSPICIOUS.value

    def test_phishing_classification(self):
        findings = [_make_finding("brand", 30), _make_finding("credentials", 30)]
        result = classify_threat(ScanType.URL, 60, findings, [])
        assert result == Classification.PHISHING.value

    def test_scam_classification(self):
        findings = [_make_finding("prize", 25), _make_finding("payment", 25)]
        result = classify_threat(ScanType.MESSAGE, 50, findings, [])
        assert result == Classification.SCAM.value


class TestConfidenceDescription:
    def test_zero_findings(self):
        conf = confidence_description(0, [], 0)
        assert "no threat indicators" in conf.lower()

    def test_with_findings_and_intel(self):
        findings = [_make_finding("brand", 30), _make_finding("vt", 40)]
        conf = confidence_description(70, findings, 2)
        assert "threat intelligence" in conf.lower() or "indicators" in conf.lower()


class TestGenerateRecommendations:
    def test_low_risk_recs(self):
        recs = generate_recommendations(RiskLevel.LOW, [], [])
        assert len(recs) >= 1

    def test_critical_risk_recs(self):
        findings = [_make_finding("credentials", 30)]
        recs = generate_recommendations(RiskLevel.CRITICAL, findings, [])
        assert len(recs) >= 3

    def test_custom_tip_included(self):
        finding_with_tip = Finding(
            indicator="credentials",
            severity=FindingSeverity.HIGH,
            evidence="Enter password",
            explanation="Asks for password",
            points=30,
            source=FindingSource.HEURISTIC,
            tip="Never submit passwords on unverified domains.",
        )
        recs = generate_recommendations(RiskLevel.HIGH, [finding_with_tip], [])
        assert any("Never submit passwords" in r for r in recs)


class TestGenerateExplanation:
    def test_zero_findings_url(self):
        exp = generate_explanation(ScanType.URL, 0, RiskLevel.LOW, Classification.SAFE.value, [], [])
        assert "No threat indicators were detected" in exp

    def test_with_findings(self):
        findings = [_make_finding("brand", 30)]
        exp = generate_explanation(ScanType.URL, 30, RiskLevel.MODERATE, Classification.SUSPICIOUS.value, findings, [])
        assert "risk score of 30/100" in exp
