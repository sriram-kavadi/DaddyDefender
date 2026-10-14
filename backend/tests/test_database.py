"""
Unit tests for Database operations.

Tests SQLite initialization, scan persistence, retrieval, stats aggregation,
deletion, and cleanup using an isolated temporary test database.
"""
import sys
import os
import uuid
import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Use a test database file
os.environ["DATABASE_PATH"] = "test_threatcheck.db"

import backend.database as db_mod


@pytest_asyncio.fixture(autouse=True)
async def setup_and_teardown_db():
    """Set up a fresh test database for each test and tear down after."""
    db_path = await db_mod.get_db_path()
    if os.path.exists(db_path):
        os.remove(db_path)
    await db_mod.init_db()
    yield
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.mark.asyncio
async def test_init_db_idempotent():
    """Ensure calling init_db multiple times does not throw errors."""
    await db_mod.init_db()
    await db_mod.init_db()


@pytest.mark.asyncio
async def test_save_and_get_scan():
    """Test saving a scan and retrieving it by ID."""
    scan_id = str(uuid.uuid4())
    scan_data = {
        "id": scan_id,
        "scan_type": "url",
        "input_preview": "http://evil-bank.xyz",
        "input_length": 21,
        "classification": "phishing",
        "risk_score": 85,
        "risk_level": "critical",
        "findings": [{"indicator": "brand", "points": 30}],
        "links": [],
        "recommendations": ["Do not click"],
        "provider_results": {},
        "explanation": "Critical threat detected",
        "limitations": "Standard limitations",
        "status": "completed",
    }
    await db_mod.save_scan(scan_data)

    retrieved = await db_mod.get_scan(scan_id)
    assert retrieved is not None
    assert retrieved["id"] == scan_id
    assert retrieved["scan_type"] == "url"
    assert retrieved["risk_score"] == 85
    assert retrieved["risk_level"] == "critical"
    assert isinstance(retrieved["findings"], list)
    assert len(retrieved["findings"]) == 1
    assert retrieved["findings"][0]["indicator"] == "brand"


@pytest.mark.asyncio
async def test_get_nonexistent_scan():
    """Retrieving an unknown ID should return None."""
    result = await db_mod.get_scan("non-existent-id")
    assert result is None


@pytest.mark.asyncio
async def test_get_recent_scans():
    """Test pagination and ordering of recent scans."""
    for i in range(5):
        scan_data = {
            "id": f"scan-{i}",
            "scan_type": "url" if i % 2 == 0 else "message",
            "input_preview": f"Test input {i}",
            "input_length": 12,
            "classification": "suspicious",
            "risk_score": i * 20,
            "risk_level": "moderate",
            "findings": [],
            "links": [],
            "recommendations": [],
            "status": "completed",
        }
        await db_mod.save_scan(scan_data)

    recent = await db_mod.get_recent_scans(limit=3, offset=0)
    assert len(recent) == 3

    paged = await db_mod.get_recent_scans(limit=3, offset=3)
    assert len(paged) == 2


@pytest.mark.asyncio
async def test_get_scan_stats():
    """Test aggregate statistics calculations."""
    scans = [
        {"id": "s1", "scan_type": "url", "risk_score": 20, "risk_level": "low"},
        {"id": "s2", "scan_type": "url", "risk_score": 60, "risk_level": "high"},
        {"id": "s3", "scan_type": "message", "risk_score": 80, "risk_level": "critical"},
    ]
    for s in scans:
        await db_mod.save_scan({
            "id": s["id"],
            "scan_type": s["scan_type"],
            "input_preview": "test",
            "input_length": 4,
            "classification": "test",
            "risk_score": s["risk_score"],
            "risk_level": s["risk_level"],
            "findings": [],
            "status": "completed",
        })

    stats = await db_mod.get_scan_stats()
    assert stats["total_scans"] == 3
    assert stats["by_type"]["url"] == 2
    assert stats["by_type"]["message"] == 1
    assert stats["by_level"]["low"] == 1
    assert stats["by_level"]["high"] == 1
    assert stats["by_level"]["critical"] == 1
    # Average score: (20 + 60 + 80) / 3 = 53.3
    assert stats["average_score"] == pytest.approx(53.3, 0.1)


@pytest.mark.asyncio
async def test_delete_scan():
    """Test deleting an existing scan and deleting a non-existent scan."""
    scan_id = "to-delete"
    await db_mod.save_scan({
        "id": scan_id,
        "scan_type": "url",
        "input_preview": "delete me",
        "input_length": 9,
        "classification": "low",
        "risk_score": 0,
        "risk_level": "low",
        "findings": [],
        "status": "completed",
    })

    deleted = await db_mod.delete_scan(scan_id)
    assert deleted is True

    # Check it's gone
    assert await db_mod.get_scan(scan_id) is None

    # Deleting again returns False
    deleted_again = await db_mod.delete_scan(scan_id)
    assert deleted_again is False
