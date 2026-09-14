from app.services.findings.finding_engine import FindingEngine


def test_high_risk_analyst_generates_finding():

    engine = FindingEngine()

    analyst = {
        "analyst_id": "AN22005",
        "organization_id": "ORG00001",
        "name": "Ananya Das",
        "risk_score": 100,
        "indicators": [
            "Suspiciously fast closure",
            "Low evidence-review rate",
            "Low escalation rate",
            "Shallow investigation activity",
            "Very short investigations",
        ],
    }

    finding = engine.analyze_analyst(analyst)

    assert finding is not None
    assert finding.finding_id == "ANALYST-AN22005"
    assert finding.category == "ANALYST_BEHAVIOR"
    assert finding.severity == "CRITICAL"
    assert finding.risk_score == 100
    assert len(finding.evidence) >= 2


def test_low_risk_analyst_does_not_generate_finding():

    engine = FindingEngine()

    analyst = {
        "analyst_id": "AN00001",
        "organization_id": "ORG00001",
        "name": "Normal Analyst",
        "risk_score": 20,
        "indicators": [],
    }

    finding = engine.analyze_analyst(analyst)

    assert finding is None


def test_multiple_findings():

    engine = FindingEngine()

    findings = engine.generate(
        analysts=[
            {
                "analyst_id": "AN001",
                "organization_id": "ORG001",
                "name": "High Risk",
                "risk_score": 90,
                "indicators": [
                    "Fast closure",
                ],
            }
        ],
        alerts=[
            {
                "alert_id": "AL001",
                "organization_id": "ORG001",
                "risk_score": 85,
                "indicators": [
                    "Evidence not reviewed",
                ],
            }
        ],
        investigations=[
            {
                "investigation_id": "INV001",
                "organization_id": "ORG001",
                "risk_score": 70,
                "indicators": [
                    "Very short investigation",
                ],
            }
        ],
    )

    assert len(findings) == 3

    assert len(
        engine.get_high_risk_findings()
    ) == 3


def test_finding_summary():

    engine = FindingEngine()

    engine.generate(
        analysts=[
            {
                "analyst_id": "AN001",
                "organization_id": "ORG001",
                "name": "Critical Analyst",
                "risk_score": 95,
                "indicators": ["Fast closure"],
            },
            {
                "analyst_id": "AN002",
                "organization_id": "ORG001",
                "name": "Medium Analyst",
                "risk_score": 50,
                "indicators": ["Minor concern"],
            },
        ]
    )

    summary = engine.summary()

    assert summary["total"] == 2
    assert summary["critical"] == 1
    assert summary["medium"] == 1
    assert summary["high_risk"] == 1