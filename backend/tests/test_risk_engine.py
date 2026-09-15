from app.services.risk_engine import (
    RiskEvidence,
    build_components,
    calculate_risk,
)


def test_low_risk():

    result = calculate_risk(
        entity_id="AN001",
        components=build_components(
            rule_score=10,
            ai_score=10,
            negative_space_score=5,
            peer_deviation_score=5,
        ),
    )

    assert result.risk_score == 8.5
    assert result.risk_level == "Low"


def test_medium_risk():

    result = calculate_risk(
        entity_id="AN002",
        components=build_components(
            rule_score=60,
            ai_score=60,
            negative_space_score=40,
            peer_deviation_score=40,
        ),
    )

    assert result.risk_score == 54.0
    assert result.risk_level == "Medium"


def test_high_risk():

    result = calculate_risk(
        entity_id="AN003",
        components=build_components(
            rule_score=100,
            ai_score=100,
            negative_space_score=100,
            peer_deviation_score=100,
        ),
    )

    assert result.risk_score == 100.0
    assert result.risk_level == "High"


def test_scores_are_clamped():

    result = calculate_risk(
        entity_id="AN004",
        components=build_components(
            rule_score=150,
            ai_score=-20,
            negative_space_score=500,
            peer_deviation_score=-100,
        ),
    )

    assert result.components.rule_score == 100.0
    assert result.components.ai_score == 0.0
    assert result.components.negative_space_score == 100.0
    assert result.components.peer_deviation_score == 0.0


def test_evidence_is_preserved():

    evidence = [
        RiskEvidence(
            source="rules",
            indicator="Suspiciously fast closure",
            severity="high",
            score_contribution=30,
            details="Critical alerts closed unusually quickly.",
        )
    ]

    result = calculate_risk(
        entity_id="AN005",
        components=build_components(
            rule_score=80,
        ),
        evidence=evidence,
    )

    assert len(result.evidence) == 1
    assert (
        result.evidence[0].indicator
        == "Suspiciously fast closure"
    )


def test_confidence_low():

    result = calculate_risk(
        entity_id="AN006",
        components=build_components(
            rule_score=50,
        ),
    )

    assert result.confidence == "Low"


def test_confidence_medium():

    evidence = [
        RiskEvidence(
            source="rules",
            indicator="Fast closure",
        ),
        RiskEvidence(
            source="behavior",
            indicator="Low investigation quality",
        ),
    ]

    result = calculate_risk(
        entity_id="AN007",
        components=build_components(
            rule_score=70,
            ai_score=60,
        ),
        evidence=evidence,
    )

    assert result.confidence == "Medium"


def test_confidence_high():

    evidence = [
        RiskEvidence(
            source="rules",
            indicator="Fast closure",
        ),
        RiskEvidence(
            source="behavior",
            indicator="Low investigation quality",
        ),
        RiskEvidence(
            source="negative_space",
            indicator="Asset silence",
        ),
    ]

    result = calculate_risk(
        entity_id="AN008",
        components=build_components(
            rule_score=80,
            ai_score=80,
            negative_space_score=80,
        ),
        evidence=evidence,
    )

    assert result.confidence == "High"


def test_to_dict():

    result = calculate_risk(
        entity_id="AN009",
        components=build_components(
            rule_score=50,
        ),
    )

    data = result.to_dict()

    assert data["entity_id"] == "AN009"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "confidence" in data
    assert "components" in data
    assert "evidence" in data