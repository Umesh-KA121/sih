from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.intelligence.supervisory_engine import (
    AnalystFinding,
    behavioral_score,
    build_metric_stats,
    clamp,
    gaming_detection,
    investigation_dna,
    jaccard_similarity,
    lightweight_nlp,
    negative_space_analysis,
    peer_benchmark_scores,
    risk_level,
    rule_intelligence,
    unified_risk,
)


# ============================================================
# Generic Helpers
# ============================================================


def test_clamp():
    assert clamp(50) == 50
    assert clamp(-10) == 0
    assert clamp(150) == 100


def test_jaccard_similarity():
    first = {"authentication", "logs", "source"}
    second = {"authentication", "logs", "endpoint"}

    score = jaccard_similarity(first, second)

    assert 0 < score < 1


def test_jaccard_similarity_empty():
    assert jaccard_similarity([], []) == 0.0


def test_jaccard_similarity_identical():
    assert jaccard_similarity(
        ["a", "b", "c"],
        ["a", "b", "c"],
    ) == 1.0


# ============================================================
# Risk Engine
# ============================================================


def test_risk_levels():
    assert risk_level(10) == "LOW"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(80) == "HIGH"
    assert risk_level(95) == "CRITICAL"


def test_risk_level_boundaries():
    assert risk_level(0) == "LOW"
    assert risk_level(24.99) == "LOW"
    assert risk_level(25) == "MEDIUM"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(50.01) == "HIGH"
    assert risk_level(89.99) == "HIGH"
    assert risk_level(90) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"


def test_unified_risk_weights():
    result = unified_risk(
        rule_score=100,
        behavior_score=0,
        negative_space_score=0,
        peer_score=0,
    )

    assert result["score"] == 40
    assert result["risk_score"] == 40
    assert result["components"]["rule_score"] == 100


def test_unified_risk_full_score():
    result = unified_risk(
        rule_score=100,
        behavior_score=100,
        negative_space_score=100,
        peer_score=100,
    )

    assert result["score"] == 100
    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"


def test_unified_risk_zero_score():
    result = unified_risk(
        rule_score=0,
        behavior_score=0,
        negative_space_score=0,
        peer_score=0,
    )

    assert result["score"] == 0
    assert result["risk_level"] == "LOW"


def test_unified_risk_clamps_inputs():
    result = unified_risk(
        rule_score=150,
        behavior_score=-10,
        negative_space_score=200,
        peer_score=-50,
    )

    assert result["components"]["rule_score"] == 100
    assert result["components"]["behavior_score"] == 0
    assert result["components"]["negative_space_score"] == 100
    assert result["components"]["peer_score"] == 0

    assert result["score"] == 60


# ============================================================
# Statistics
# ============================================================


def test_build_metric_stats():
    stats = build_metric_stats(
        [10, 20, 30, 40, 50]
    )

    assert stats.mean == 30
    assert stats.median == 30
    assert stats.minimum == 10
    assert stats.maximum == 50
    assert stats.p90 > 0
    assert stats.p95 > 0


def test_build_metric_stats_empty():
    stats = build_metric_stats([])

    assert stats.mean == 0
    assert stats.stddev == 0
    assert stats.median == 0
    assert stats.minimum == 0
    assert stats.maximum == 0


# ============================================================
# Rule Intelligence
# ============================================================


def make_metrics(
    *,
    average_closure_time=60,
    evidence_review_rate=100,
    escalation_rate=100,
    investigation_count=10,
    average_investigation_duration=60,
    critical_alert_count=0,
    critical_escalation_rate=100,
):
    return {
        "alert_count": 10,
        "investigation_count": investigation_count,
        "average_closure_time": average_closure_time,
        "average_investigation_duration":
            average_investigation_duration,
        "evidence_review_rate":
            evidence_review_rate,
        "escalation_rate":
            escalation_rate,
        "critical_alert_count":
            critical_alert_count,
        "critical_escalation_rate":
            critical_escalation_rate,
    }


def test_rule_intelligence_clean_analyst():
    metrics = make_metrics()

    result = rule_intelligence(
        metrics,
        [],
        [],
    )

    assert result["score"] == 0
    assert result["findings"] == []


def test_rule_fast_closure():
    metrics = make_metrics(
        average_closure_time=5,
    )

    result = rule_intelligence(
        metrics,
        [],
        [],
    )

    rules = {
        finding["rule"]
        for finding in result["findings"]
    }

    assert "FAST_CLOSURE" in rules
    assert result["score"] >= 20


def test_rule_no_evidence():
    metrics = make_metrics(
        evidence_review_rate=20,
    )

    alert = SimpleNamespace(
        evidence_reviewed=False,
    )

    result = rule_intelligence(
        metrics,
        [alert],
        [],
    )

    rules = {
        finding["rule"]
        for finding in result["findings"]
    }

    assert "NO_EVIDENCE" in rules


def test_rule_no_escalation_for_critical():
    metrics = make_metrics(
        critical_alert_count=4,
        critical_escalation_rate=10,
    )

    result = rule_intelligence(
        metrics,
        [SimpleNamespace()],
        [],
    )

    rules = {
        finding["rule"]
        for finding in result["findings"]
    }

    assert "NO_ESCALATION" in rules


def test_rule_repeated_notes():
    metrics = make_metrics()

    investigations = [
        SimpleNamespace(
            investigation_notes="same investigation note"
        ),
        SimpleNamespace(
            investigation_notes="same investigation note"
        ),
        SimpleNamespace(
            investigation_notes="another investigation"
        ),
    ]

    result = rule_intelligence(
        metrics,
        [],
        investigations,
    )

    rules = {
        finding["rule"]
        for finding in result["findings"]
    }

    assert "REPEATED_NOTES" in rules


# ============================================================
# Investigation DNA
# ============================================================


def test_investigation_dna_empty():
    result = investigation_dna(
        [],
        [],
    )

    assert result["score"] == 0
    assert result["evidence_discipline"] == 0


def test_investigation_dna():
    alerts = [
        SimpleNamespace(
            evidence_reviewed=True,
            closure_time_minutes=60,
        ),
        SimpleNamespace(
            evidence_reviewed=True,
            closure_time_minutes=60,
        ),
    ]

    investigations = [
        SimpleNamespace(
            duration_minutes=30,
            queries_executed=5,
            actions_performed="search,review,verify",
            investigation_notes=(
                "Reviewed evidence and determined the root cause."
            ),
        )
    ]

    result = investigation_dna(
        alerts,
        investigations,
    )

    assert 0 <= result["score"] <= 100
    assert result["evidence_discipline"] == 100
    assert result["query_activity"] > 0
    assert result["action_activity"] > 0
    assert result["note_quality"] > 0


# ============================================================
# Lightweight NLP
# ============================================================


def test_lightweight_nlp_empty():
    result = lightweight_nlp(
        [],
        [],
    )

    assert result["score"] == 0
    assert result["note_count"] == 0


def test_lightweight_nlp():
    alerts = [
        SimpleNamespace(
            investigation_notes=(
                "Evidence from logs and IP address was reviewed. "
                "Finding confirmed."
            )
        )
    ]

    investigations = [
        SimpleNamespace(
            investigation_notes=(
                "The analyst reviewed packet traces and logs. "
                "Conclusion was documented."
            )
        )
    ]

    result = lightweight_nlp(
        alerts,
        investigations,
    )

    assert result["note_count"] == 2
    assert result["average_words"] > 0
    assert result["evidence_reference_rate"] > 0
    assert result["finding_conclusion_rate"] > 0
    assert 0 <= result["score"] <= 100


def test_lightweight_nlp_repetition():
    note = (
        "Reviewed logs and evidence. "
        "Finding confirmed."
    )

    alerts = [
        SimpleNamespace(
            investigation_notes=note
        ),
        SimpleNamespace(
            investigation_notes=note
        ),
    ]

    result = lightweight_nlp(
        alerts,
        [],
    )

    assert result["repetition_rate"] == 50


# ============================================================
# Gaming Detection
# ============================================================


def test_gaming_detection_empty():
    result = gaming_detection(
        [],
        [],
    )

    assert result["score"] == 0
    assert result["indicators"] == []


def test_gaming_repeated_notes():
    investigations = [
        SimpleNamespace(
            investigation_notes="identical note"
        ),
        SimpleNamespace(
            investigation_notes="identical note"
        ),
        SimpleNamespace(
            investigation_notes="identical note"
        ),
        SimpleNamespace(
            investigation_notes="different note"
        ),
    ]

    result = gaming_detection(
        [],
        investigations,
    )

    assert result["repetition_rate"] >= 50
    assert "Repeated investigation notes" in (
        result["indicators"]
    )


def test_gaming_uniform_closure_duration():
    alerts = [
        SimpleNamespace(
            closure_time_minutes=5,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=5,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=5,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=20,
            status="OPEN",
        ),
    ]

    result = gaming_detection(
        alerts,
        [],
    )

    assert result["repeated_closure_rate"] >= 50
    assert (
        "Suspiciously uniform closure durations"
        in result["indicators"]
    )


def test_gaming_uniform_workflow():
    alerts = [
        SimpleNamespace(
            closure_time_minutes=5,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=10,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=8,
            status="CLOSED",
        ),
        SimpleNamespace(
            closure_time_minutes=12,
            status="CLOSED",
        ),
    ]

    result = gaming_detection(
        alerts,
        [],
    )

    assert (
        result["dominant_workflow_rate"] >= 90
    )
    assert (
        "Suspiciously uniform workflow"
        in result["indicators"]
    )


# ============================================================
# Negative Space
# ============================================================


def test_negative_space_critical_asset_silence():
    analyst = SimpleNamespace(
        analyst_id="A001"
    )

    assets = [
        SimpleNamespace(
            asset_id="ASSET001",
            criticality="CRITICAL",
        )
    ]

    findings = negative_space_analysis(
        analyst,
        [],
        [],
        assets,
        [],
    )

    categories = {
        item["category"]
        for item in findings
    }

    assert "CRITICAL_ASSET_SILENCE" in categories


def test_negative_space_high_alert_without_investigation():
    analyst = SimpleNamespace(
        analyst_id="A001"
    )

    alert = SimpleNamespace(
        alert_id="ALERT001",
        analyst_id="A001",
        severity="HIGH",
        status="OPEN",
        escalated=False,
    )

    findings = negative_space_analysis(
        analyst,
        [alert],
        [],
        [],
        [],
    )

    categories = {
        item["category"]
        for item in findings
    }

    assert (
        "EXPECTED_INVESTIGATION_MISSING"
        in categories
    )


def test_negative_space_critical_closed_without_escalation():
    analyst = SimpleNamespace(
        analyst_id="A001"
    )

    alert = SimpleNamespace(
        alert_id="ALERT002",
        analyst_id="A001",
        severity="CRITICAL",
        status="CLOSED",
        escalated=False,
    )

    findings = negative_space_analysis(
        analyst,
        [alert],
        [],
        [],
        [],
    )

    categories = {
        item["category"]
        for item in findings
    }

    assert (
        "EXPECTED_ESCALATION_MISSING"
        in categories
    )


def test_negative_space_high_activity_without_alert():
    analyst = SimpleNamespace(
        analyst_id="A001"
    )

    asset = SimpleNamespace(
        asset_id="ASSET002",
        criticality="HIGH",
    )

    activity = SimpleNamespace(
        asset_id="ASSET002",
        event_count=5000,
        network_events=1000,
        authentication_events=1000,
        log_sources_active=10,
        timestamp=None,
    )

    findings = negative_space_analysis(
        analyst,
        [],
        [],
        [asset],
        [activity],
    )

    categories = {
        item["category"]
        for item in findings
    }

    assert (
        "EXPECTED_ALERT_MISSING"
        in categories
    )


# ============================================================
# Peer Benchmark
# ============================================================


def test_peer_benchmark_centered_analyst():
    all_metrics = {
        "A001": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
            "investigation_count": 5,
            "average_investigation_duration": 30,
        },
        "A002": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
            "investigation_count": 5,
            "average_investigation_duration": 30,
        },
        "A003": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
            "investigation_count": 5,
            "average_investigation_duration": 30,
        },
    }

    result = peer_benchmark_scores(
        all_metrics,
        "A001",
    )

    assert 0 <= result["score"] <= 100
    assert result["average_deviation"] == 0


def test_peer_benchmark_outlier():
    all_metrics = {
        "A001": {
            "alert_count": 100,
            "average_closure_time": 2,
            "evidence_review_rate": 10,
            "escalation_rate": 1,
            "investigation_count": 1,
            "average_investigation_duration": 2,
        },
        "A002": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 90,
            "escalation_rate": 30,
            "investigation_count": 10,
            "average_investigation_duration": 30,
        },
        "A003": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 90,
            "escalation_rate": 30,
            "investigation_count": 10,
            "average_investigation_duration": 30,
        },
    }

    result = peer_benchmark_scores(
        all_metrics,
        "A001",
    )

    assert result["score"] > 0
    assert result["average_deviation"] > 0


# ============================================================
# Behavioral Analytics
# ============================================================


def test_behavioral_score_centered():
    all_metrics = {
        "A001": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
        },
        "A002": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
        },
        "A003": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 80,
            "escalation_rate": 20,
        },
    }

    result = behavioral_score(
        all_metrics,
        "A001",
    )

    assert 0 <= result["score"] <= 100

    for value in result["deviations"].values():
        assert value == 0


def test_behavioral_score_outlier():
    all_metrics = {
        "A001": {
            "alert_count": 100,
            "average_closure_time": 2,
            "evidence_review_rate": 10,
            "escalation_rate": 1,
        },
        "A002": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 90,
            "escalation_rate": 30,
        },
        "A003": {
            "alert_count": 10,
            "average_closure_time": 30,
            "evidence_review_rate": 90,
            "escalation_rate": 30,
        },
    }

    result = behavioral_score(
        all_metrics,
        "A001",
    )

    assert result["score"] > 0


# ============================================================
# Dataclass Contract
# ============================================================


def test_analyst_finding_defaults():
    finding = AnalystFinding(
        analyst_id="A001",
        analyst_name="Test Analyst",
    )

    assert finding.analyst_id == "A001"
    assert finding.analyst_name == "Test Analyst"
    assert finding.score == 0
    assert finding.risk_level == "LOW"
    assert finding.indicators == []
    assert finding.rule_findings == []
    assert finding.negative_space == []