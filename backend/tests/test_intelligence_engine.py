from app.services.intelligence.supervisory_engine import (
    clamp,
    jaccard_similarity,
    risk_level,
    unified_risk,
)


def test_clamp():

    assert clamp(50) == 50
    assert clamp(-10) == 0
    assert clamp(150) == 100


def test_jaccard_similarity():

    first = {
        "authentication",
        "logs",
        "source",
    }

    second = {
        "authentication",
        "logs",
        "endpoint",
    }

    score = jaccard_similarity(
        first,
        second,
    )

    assert 0 < score < 1


def test_risk_levels():

    assert risk_level(10) == "LOW"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(80) == "HIGH"
    assert risk_level(95) == "CRITICAL"


def test_unified_risk_weights():

    result = unified_risk(
        rule_score=100,
        behavior_score=0,
        negative_space_score=0,
        peer_score=0,
    )

    assert result["score"] == 40


def test_unified_risk_full_score():

    result = unified_risk(
        rule_score=100,
        behavior_score=100,
        negative_space_score=100,
        peer_score=100,
    )

    assert result["score"] == 100