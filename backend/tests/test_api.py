from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root():

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["name"] == "SAT-SA"


def test_health():

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_dashboard_overview():

    response = client.get(
        "/api/v1/dashboard/overview"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data
    assert "total_alerts" in data["data"]


def test_dashboard_risk():

    response = client.get(
        "/api/v1/dashboard/risk-summary"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "overall_risk_score" in data["data"]


def test_alert_api():

    response = client.get(
        "/api/v1/alerts?limit=5"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data
    assert data["limit"] == 5


def test_analyst_api():

    response = client.get(
        "/api/v1/analysts?limit=5"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data


def test_asset_api():

    response = client.get(
        "/api/v1/assets?limit=5"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data


def test_investigation_api():

    response = client.get(
        "/api/v1/investigations?limit=5"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data


def test_findings_api():

    response = client.get(
        "/api/v1/findings"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "data" in data


def test_finding_summary():

    response = client.get(
        "/api/v1/findings/summary"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "total" in data