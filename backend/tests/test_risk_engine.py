from app.services.risk.risk_engine import RiskEngine


def test_analyst_risk():

    engine = RiskEngine()

    result = engine.analyst_risk(
        closure_risk=100,
        evidence_review_risk=100,
        escalation_risk=80,
        investigation_risk=90,
    )

    assert result.score >= 80
    assert result.severity == "CRITICAL"
    assert len(result.factors) >= 3


def test_low_risk_analyst():

    engine = RiskEngine()

    result = engine.analyst_risk(
        closure_risk=10,
        evidence_review_risk=10,
        escalation_risk=10,
        investigation_risk=10,
    )

    assert result.score < 40
    assert result.severity == "LOW"


def test_alert_risk():

    engine = RiskEngine()

    result = engine.alert_risk(
        severity_risk=100,
        closure_risk=80,
        evidence_risk=90,
        escalation_risk=80,
        false_positive_risk=20,
    )

    assert result.score >= 60
    assert result.severity in {
        "HIGH",
        "CRITICAL",
    }