"""
Pydantic models for request/response validation in Threat Check.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from enum import Enum


# --- Enums ---

class ScanType(str, Enum):
    URL = "url"
    MESSAGE = "message"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    SAFE = "no significant threat detected"
    SUSPICIOUS = "suspicious"
    POTENTIALLY_FRAUDULENT = "potentially fraudulent"
    PHISHING = "phishing"
    SCAM = "scam"
    INCONCLUSIVE = "inconclusive"


class FindingSource(str, Enum):
    HEURISTIC = "heuristic"
    INTELLIGENCE = "threat-intelligence"
    AI = "ai-assisted"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# --- Request Models ---

class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The URL to analyze for threats",
        examples=["http://paypa1-secure-login.xyz/verify?session=48213"]
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 10000:
            raise ValueError("URL exceeds maximum length of 10000 characters")
        return v


class MessageAnalysisRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The message text to analyze for threats",
        examples=["URGENT: Your bank account has been suspended. Click here to verify: http://secure-update.xyz"]
    )

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty")
        if len(v) > 10000:
            raise ValueError("Message exceeds maximum length of 10000 characters")
        return v


# --- Response Models ---

class Finding(BaseModel):
    """Individual threat indicator finding."""
    indicator: str = Field(..., description="Short name of the indicator")
    severity: FindingSeverity = Field(..., description="Severity level of this finding")
    evidence: str = Field(..., description="Specific evidence that triggered this finding")
    explanation: str = Field(..., description="Human-readable explanation of why this matters")
    points: int = Field(..., ge=0, le=100, description="Points contributed to risk score")
    source: FindingSource = Field(
        default=FindingSource.HEURISTIC,
        description="Source of this finding"
    )
    tip: Optional[str] = Field(None, description="Actionable recommendation for this finding")


class LinkAnalysis(BaseModel):
    """Analysis result for a URL found within a message."""
    url: str
    host: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    findings: list[Finding] = []


class ProviderResult(BaseModel):
    """Result from a threat intelligence provider."""
    provider: str = Field(..., description="Name of the provider")
    available: bool = Field(..., description="Whether the provider was reachable")
    status: str = Field(..., description="Lookup status: configured, unavailable, error, success")
    result: Optional[dict] = Field(None, description="Provider-specific result data")
    error: Optional[str] = Field(None, description="Error message if lookup failed")


class ScanResponse(BaseModel):
    """Structured response for all scan types."""
    scan_id: str = Field(..., description="Unique identifier for this scan")
    scan_type: ScanType
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    input_summary: str = Field(
        ...,
        description="Redacted/truncated summary of the input"
    )
    classification: str = Field(
        ...,
        description="Threat classification"
    )
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    risk_level: RiskLevel
    confidence: str = Field(
        ...,
        description="Description of evidence strength"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Individual threat indicators found"
    )
    links: list[LinkAnalysis] = Field(
        default_factory=list,
        description="URLs found and analyzed (for message scans)"
    )
    provider_results: list[ProviderResult] = Field(
        default_factory=list,
        description="Results from threat intelligence providers"
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Safety recommendations"
    )
    explanation: str = Field(
        ...,
        description="Human-readable summary explanation"
    )
    limitations: str = Field(
        ...,
        description="What this analysis cannot determine"
    )
    status: str = Field(default="completed", description="Scan processing status")


class ScanHistoryItem(BaseModel):
    """Abbreviated scan for history listings."""
    scan_id: str
    scan_type: ScanType
    input_preview: str
    risk_score: int
    risk_level: RiskLevel
    classification: str
    created_at: str


class ScanHistoryResponse(BaseModel):
    """Response for scan history endpoint."""
    scans: list[ScanHistoryItem]
    total: int


class StatsResponse(BaseModel):
    """Aggregate statistics response."""
    total_scans: int
    by_level: dict[str, int]
    by_type: dict[str, int]
    average_score: float


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = "1.0.0"
    database: str = "connected"
    providers: dict[str, str] = {}


class ErrorResponse(BaseModel):
    """Standardized error response."""
    error: str
    detail: str
    status_code: int
