"""
Scan history API routes for Threat Check.

GET /api/scans - List recent scans
GET /api/scans/{scan_id} - Retrieve a specific scan
DELETE /api/scans/{scan_id} - Delete a specific scan
GET /api/scans/stats - Get aggregate statistics
"""
import logging

from fastapi import APIRouter, HTTPException, Query

from backend.models import ScanHistoryItem, ScanHistoryResponse, StatsResponse, ScanType, RiskLevel
from backend.database import get_scan, get_recent_scans, get_scan_stats, delete_scan

logger = logging.getLogger("threatcheck.scans")

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get(
    "",
    response_model=ScanHistoryResponse,
    summary="List recent scans",
    description="Retrieve scan history, ordered by most recent first.",
)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of scans to return"),
    offset: int = Query(default=0, ge=0, description="Number of scans to skip"),
):
    """List recent scans from the database."""
    scans = await get_recent_scans(limit=limit, offset=offset)

    items = []
    for scan in scans:
        try:
            items.append(ScanHistoryItem(
                scan_id=scan["id"],
                scan_type=ScanType(scan["scan_type"]),
                input_preview=scan.get("input_preview", ""),
                risk_score=scan["risk_score"],
                risk_level=RiskLevel(scan["risk_level"]),
                classification=scan.get("classification", "unknown"),
                created_at=scan.get("created_at", ""),
            ))
        except (ValueError, KeyError) as e:
            logger.warning(f"Skipping malformed scan record: {e}")
            continue

    stats = await get_scan_stats()
    return ScanHistoryResponse(scans=items, total=stats["total_scans"])


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Get scan statistics",
    description="Retrieve aggregate statistics from all scans.",
)
async def scan_stats():
    """Get aggregate statistics computed from actual persisted data."""
    stats = await get_scan_stats()
    return StatsResponse(**stats)


@router.get(
    "/{scan_id}",
    summary="Retrieve a specific scan",
    description="Get the full details of a previously completed scan.",
)
async def get_scan_details(scan_id: str):
    """Retrieve a scan by its ID."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete(
    "/{scan_id}",
    summary="Delete a specific scan",
    description="Remove a scan from history.",
)
async def delete_scan_endpoint(scan_id: str):
    """Delete a scan record."""
    deleted = await delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "scan_id": scan_id}
