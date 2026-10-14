"""
Integration and API endpoint tests for Threat Check backend.

Tests:
- Health check endpoint (/api/health)
- URL threat analysis (/api/analyze/url)
- Message threat analysis (/api/analyze/message)
- Scan history listing (/api/scans)
- Scan detail retrieval (/api/scans/{id})
- Aggregate stats (/api/scans/stats)
- Scan deletion (/api/scans/{id})
- Validation errors and 404s
"""
import sys
import os
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Set test environment
os.environ["DATABASE_PATH"] = "test_api_threatcheck.db"

from backend.main import app
import backend.database as db_mod


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    """Ensure database is initialized for API tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(db_mod.init_db())
    yield
    db_path = loop.run_until_complete(db_mod.get_db_path())
    if os.path.exists(db_path):
        os.remove(db_path)
    loop.close()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "providers" in data


class TestAnalyzeUrlEndpoint:
    def test_analyze_valid_safe_url(self, client):
        response = client.post("/api/analyze/url", json={"url": "https://www.google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["scan_type"] == "url"
        assert "scan_id" in data
        assert data["risk_score"] < 25
        assert data["risk_level"] == "low"
        assert "recommendations" in data
        assert "limitations" in data

    def test_analyze_suspicious_url(self, client):
        response = client.post("/api/analyze/url", json={"url": "http://paypa1-security-update.xyz/login"})
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] >= 50
        assert data["risk_level"] in ["high", "critical"]
        assert len(data["findings"]) > 0

    def test_analyze_invalid_url(self, client):
        response = client.post("/api/analyze/url", json={"url": "not a url"})
        assert response.status_code == 400

    def test_analyze_empty_url(self, client):
        response = client.post("/api/analyze/url", json={"url": ""})
        assert response.status_code == 422


class TestAnalyzeMessageEndpoint:
    def test_analyze_safe_message(self, client):
        response = client.post("/api/analyze/message", json={"message": "Hey, let's meet tomorrow at the office at 2pm."})
        assert response.status_code == 200
        data = response.json()
        assert data["scan_type"] == "message"
        assert data["risk_score"] < 25
        assert data["risk_level"] == "low"

    def test_analyze_phishing_message(self, client):
        message = (
            "URGENT: Your bank account will be suspended in 24 hours. "
            "Verify your identity and card number immediately at: http://secure-bank-login.xyz/verify. "
            "Do not share this with anyone."
        )
        response = client.post("/api/analyze/message", json={"message": message})
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] >= 50
        assert data["risk_level"] in ["high", "critical"]
        assert len(data["links"]) >= 1
        assert len(data["findings"]) > 0

    def test_analyze_empty_message(self, client):
        response = client.post("/api/analyze/message", json={"message": ""})
        assert response.status_code == 422


class TestScansAndHistory:
    def test_scans_list_and_details_and_deletion(self, client):
        # 1. Perform a scan to ensure there is at least one item
        scan_resp = client.post("/api/analyze/url", json={"url": "https://example.com/test-scan"})
        assert scan_resp.status_code == 200
        scan_id = scan_resp.json()["scan_id"]

        # 2. Check scans list
        list_resp = client.get("/api/scans")
        assert list_resp.status_code == 200
        data = list_resp.json()
        assert "scans" in data
        assert any(s["scan_id"] == scan_id for s in data["scans"])

        # 3. Retrieve specific scan details
        detail_resp = client.get(f"/api/scans/{scan_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["id"] == scan_id

        # 4. Check statistics
        stats_resp = client.get("/api/scans/stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_scans"] >= 1

        # 5. Delete the scan
        del_resp = client.delete(f"/api/scans/{scan_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "deleted"

        # 6. Retrieve after delete should be 404
        get_after = client.get(f"/api/scans/{scan_id}")
        assert get_after.status_code == 404
