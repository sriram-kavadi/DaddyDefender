"""
Analysis API routes for Threat Check.

POST /api/analyze/url - Analyze a URL for threats
POST /api/analyze/message - Analyze a message for threats
"""
import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from backend.models import (
    URLAnalysisRequest,
    MessageAnalysisRequest,
    ScanResponse,
    ScanType,
    RiskLevel,
    ErrorResponse,
)
from backend.analysis.url_analyzer import analyze_url
from backend.analysis.message_analyzer import analyze_message
from backend.analysis.scoring import (
    level_for,
    classify_threat,
    confidence_description,
    generate_recommendations,
    generate_explanation,
    generate_ai_explanation,
    LIMITATIONS_TEXT,
)
from backend.analysis.threat_intel import check_all_providers
from backend.database import save_scan

logger = logging.getLogger("threatcheck.routes")

router = APIRouter(prefix="/api/analyze", tags=["analysis"])

PREVIEW_LEN = 80


def _input_preview(text: str) -> str:
    """Create a redacted preview of user input for storage."""
    preview = " ".join(text.split())
    if len(preview) > PREVIEW_LEN:
        return preview[:PREVIEW_LEN] + "..."
    return preview


@router.post(
    "/url",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Analyze a URL for threat indicators",
    description="Submit a URL for passive analysis. The URL is never visited or followed.",
)
async def analyze_url_endpoint(request: URLAnalysisRequest):
    """Analyze a URL for phishing, brand impersonation, and other threats."""
    raw_url = request.url.strip()

    # Run heuristic URL analysis
    result = analyze_url(raw_url)

    if "error" in result and result["error"] == "invalid-url":
        raise HTTPException(
            status_code=400,
            detail="That does not look like a valid web address.",
        )

    findings = result.get("findings", [])
    score = result.get("score", 0)

    # Query threat intelligence providers
    provider_results = []
    intel_findings = []
    normalized = result.get("normalized", raw_url)
    try:
        provider_results, intel_findings = await check_all_providers(normalized)
        # Add intel findings and recalculate score
        if intel_findings:
            findings.extend(intel_findings)
            score = min(100, sum(f.points for f in findings))
    except Exception as e:
        logger.error(f"Threat intelligence error: {e}")

    level = level_for(score)
    classification = classify_threat(ScanType.URL, score, findings, [])
    confidence = confidence_description(score, findings, len(provider_results))
    recommendations = generate_recommendations(level, findings, [])
    explanation = await generate_ai_explanation(ScanType.URL, score, level, classification, findings, [], raw_url)

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    response = ScanResponse(
        scan_id=scan_id,
        scan_type=ScanType.URL,
        timestamp=timestamp,
        input_summary=_input_preview(raw_url),
        classification=classification,
        risk_score=score,
        risk_level=level,
        confidence=confidence,
        findings=findings,
        links=[],
        provider_results=provider_results,
        recommendations=recommendations,
        explanation=explanation,
        limitations=LIMITATIONS_TEXT,
        status="completed",
    )

    # Persist to database
    try:
        await save_scan({
            "id": scan_id,
            "scan_type": ScanType.URL.value,
            "input_preview": _input_preview(raw_url),
            "input_length": len(raw_url),
            "classification": classification,
            "risk_score": score,
            "risk_level": level.value,
            "findings": [f.model_dump() for f in findings],
            "links": [],
            "recommendations": recommendations,
            "provider_results": {pr.provider: pr.model_dump() for pr in provider_results},
            "explanation": explanation,
            "limitations": LIMITATIONS_TEXT,
            "status": "completed",
            "created_at": timestamp,
        })
    except Exception as e:
        logger.error(f"Failed to persist scan: {e}")
        # Don't fail the response just because persistence failed

    return response


@router.post(
    "/message",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Analyze a message for threat indicators",
    description="Submit a message (email, SMS, chat) for phishing and scam analysis.",
)
async def analyze_message_endpoint(request: MessageAnalysisRequest):
    """Analyze a message for phishing, scam, and social engineering indicators."""
    text = request.message.strip()

    # Run message analysis
    result = analyze_message(text)

    findings = result.get("findings", [])
    links = result.get("links", [])
    score = result.get("score", 0)

    # Query threat intelligence for links found in the message
    provider_results = []
    intel_findings = []
    for link in links:
        try:
            prov_res, i_findings = await check_all_providers(link.url)
            provider_results.extend(prov_res)
            if i_findings:
                # Add intel findings to the link's findings
                link.findings.extend(i_findings)
                link.risk_score = min(100, sum(f.points for f in link.findings))
                link.risk_level = level_for(link.risk_score)
                intel_findings.extend(i_findings)
        except Exception as e:
            logger.error(f"Threat intelligence error for link {link.url}: {e}")

    # Consolidate provider results by provider name (prioritizing positive matches)
    deduped_providers: dict[str, ProviderResult] = {}
    for pr in provider_results:
        if pr.provider not in deduped_providers or pr.status == "found":
            deduped_providers[pr.provider] = pr
    provider_results = list(deduped_providers.values())

    # Recalculate message score if intel findings were added
    if intel_findings:
        max_link_score = max((l.risk_score for l in links), default=0)
        score = min(100, sum(f.points for f in findings) + max_link_score)

    level = level_for(score)
    classification = classify_threat(ScanType.MESSAGE, score, findings, links)
    confidence = confidence_description(score, findings, len(provider_results))
    recommendations = generate_recommendations(level, findings, links)
    explanation = await generate_ai_explanation(ScanType.MESSAGE, score, level, classification, findings, links, text)

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    response = ScanResponse(
        scan_id=scan_id,
        scan_type=ScanType.MESSAGE,
        timestamp=timestamp,
        input_summary=_input_preview(text),
        classification=classification,
        risk_score=score,
        risk_level=level,
        confidence=confidence,
        findings=findings,
        links=links,
        provider_results=provider_results,
        recommendations=recommendations,
        explanation=explanation,
        limitations=LIMITATIONS_TEXT,
        status="completed",
    )

    # Persist to database
    try:
        await save_scan({
            "id": scan_id,
            "scan_type": ScanType.MESSAGE.value,
            "input_preview": _input_preview(text),
            "input_length": len(text),
            "classification": classification,
            "risk_score": score,
            "risk_level": level.value,
            "findings": [f.model_dump() for f in findings],
            "links": [l.model_dump() for l in links],
            "recommendations": recommendations,
            "provider_results": {pr.provider: pr.model_dump() for pr in provider_results},
            "explanation": explanation,
            "limitations": LIMITATIONS_TEXT,
            "status": "completed",
            "created_at": timestamp,
        })
    except Exception as e:
        logger.error(f"Failed to persist scan: {e}")

    return response
