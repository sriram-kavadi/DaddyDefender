"""
Health check route for Threat Check.

GET /api/health - Returns application health status and provider configuration.
"""
from fastapi import APIRouter

from backend.models import HealthResponse
from backend.analysis.threat_intel import get_provider_status

router = APIRouter(tags=["health"])


@router.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns the application health status and provider availability.",
)
async def health_check():
    """Check application health and provider configuration."""
    providers = get_provider_status()

    return HealthResponse(
        status="ok",
        version="1.0.0",
        database="connected",
        providers=providers,
    )
