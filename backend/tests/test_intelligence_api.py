from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.intelligence import api_service


client = TestClient(app)


# ============================================================
# Mock Engine Result
# ============================================================

MOCK_RESULT = {
    "engine_version": "2.1",
    "generated_at": "2026-09-15T00:00:00",
    "summary": {
        "analysts_analyzed": 3,
        "findings": 2,
        "high_risk": 1,
        "critical_risk": 0,
    },
}


MOCK_FINDINGS = [
    {
        "analyst_id": "A001",
        "analyst_name": "Test Analyst",
        "score": 75.0,
        "risk_level": "HIGH",
        "rule_score": 60.0,
        "behavior_score": 70.0,
        "negative_space_score": 80.0,
        "peer_score": 50.0,
        "indicators": [
            "FAST_CLOSURE",
            "NO_EVIDENCE",
        ],
    },
    {
        "analyst_id": "A002",
        "analyst_name": "Another Analyst",
        "score": 20.0,
        "risk_level": "LOW",
        "rule_score": 10.0,
        "behavior_score": 20.0,
        "negative_space_score": 15.0,
        "peer_score": 20.0,
        "indicators": [],
    },
]


# ============================================================
# Helpers
# ============================================================


def fake_run_supervisory_analysis(
    force_refresh: bool = False,
):
    return MOCK_RESULT


def fake_get_summary(
    result=None,
):
    return MOCK_RESULT["summary"]


def fake_get_findings(
    result=None,
):
    return MOCK_FINDINGS


def fake_get_analyst_findings(
    result=None,
    analyst_id=None,
):
    return [
        finding
        for finding in MOCK_FINDINGS
        if finding["analyst_id"] == analyst_id
    ]


def fake_get_analyst_finding(
    result=None,
    analyst_id=None,
):
    for finding in MOCK_FINDINGS:
        if finding["analyst_id"] == analyst_id:
            return finding

    return None


def fake_clear_engine_cache():
    return None


# ============================================================
# Fixtures
# ============================================================


def setup_api_mocks(monkeypatch):
    monkeypatch.setattr(
        api_service,
        "run_supervisory_analysis",
        fake_run_supervisory_analysis,
    )

    monkeypatch.setattr(
        api_service,
        "get_summary",
        fake_get_summary,
    )

    monkeypatch.setattr(
        api_service,
        "get_findings",
        fake_get_findings,
    )

    monkeypatch.setattr(
        api_service,
        "get_analyst_findings",
        fake_get_analyst_findings,
    )

    monkeypatch.setattr(
        api_service,
        "get_analyst_finding",
        fake_get_analyst_finding,
    )

    monkeypatch.setattr(
        api_service,
        "clear_engine_cache",
        fake_clear_engine_cache,
    )


# ============================================================
# Intelligence Summary
# ============================================================


def test_intelligence_summary(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/summary"
    )

    assert response.status_code == 200

    data = response.json()

    assert "summary" in data
    assert data["engine_version"] == "2.1"
    assert data["summary"]["analysts_analyzed"] == 3


def test_intelligence_summary_refresh(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/summary?refresh=true"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["engine_version"] == "2.1"


# ============================================================
# All Findings
# ============================================================


def test_intelligence_findings(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/findings"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 2
    assert len(data["findings"]) == 2


def test_intelligence_findings_refresh(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/findings?refresh=true"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 2


# ============================================================
# Analyst Finding
# ============================================================


def test_intelligence_analyst(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/analysts/A001"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["analyst_id"] == "A001"
    assert data["analyst_name"] == "Test Analyst"
    assert data["score"] == 75.0
    assert data["risk_level"] == "HIGH"

def test_intelligence_analyst_findings(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/analysts/A001/findings"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["analyst_id"] == "A001"
    assert data["count"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["analyst_id"] == "A001"

def test_intelligence_analyst_not_found(monkeypatch):
    setup_api_mocks(monkeypatch)

    response = client.get(
        "/intelligence/analysts/UNKNOWN"
    )

    assert response.status_code == 404