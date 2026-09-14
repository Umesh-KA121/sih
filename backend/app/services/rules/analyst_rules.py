"""Reusable rule-based analyst behavior evaluation for SAT-SA."""


def evaluate_analyst_behavior(
    *,
    total_alerts: int,
    closed_alerts: int,
    avg_closure_time: float | None,
    evidence_review_rate: float,
    escalation_rate: float,
    total_investigations: int,
    avg_queries: float,
    avg_investigation_time: float | None,
) -> dict:
    """Evaluate analyst behavior using explainable deterministic rules."""

    indicators: list[str] = []
    risk_score = 0

    # Informational only: high workload is not suspicious by itself.
    if total_alerts >= 100:
        indicators.append("High alert workload")

    if (
        avg_closure_time is not None
        and avg_closure_time < 10
        and closed_alerts >= 1
    ):
        risk_score += 30
        indicators.append("Suspiciously fast closure")

    if total_alerts >= 1 and evidence_review_rate < 50:
        risk_score += 20
        indicators.append("Low evidence-review rate")

    if total_alerts >= 2 and escalation_rate < 10:
        risk_score += 15
        indicators.append("Low escalation rate")

    if total_investigations >= 1 and avg_queries < 2:
        risk_score += 20
        indicators.append("Shallow investigation activity")

    if (
        total_investigations >= 1
        and avg_investigation_time is not None
        and avg_investigation_time < 10
    ):
        risk_score += 15
        indicators.append("Very short investigations")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Confidence is based on the amount of observed activity.
    if total_alerts >= 5:
        confidence = "High"
    elif total_alerts >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "score": risk_score,
        "level": risk_level,
        "confidence": confidence,
        "indicators": indicators,
    }
