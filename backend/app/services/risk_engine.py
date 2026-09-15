"""
SAT-SA Risk Engine

Combines outputs from:
    1. Rule Intelligence
    2. Behavioral / AI / NLP analysis
    3. Negative-space analysis
    4. Peer benchmarking

Final score:

    Risk =
        Rule Score           * 0.40
      + AI Score             * 0.30
      + Negative Space Score * 0.20
      + Peer Score           * 0.10

Risk levels:

    0  - 39  -> Low
    40 - 70  -> Medium
    > 70     -> High

The engine is intentionally pure Python so it does not depend
on NumPy/scikit-learn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ============================================================
# WEIGHTS
# ============================================================

RULE_WEIGHT = 0.40
AI_WEIGHT = 0.30
NEGATIVE_SPACE_WEIGHT = 0.20
PEER_WEIGHT = 0.10


# ============================================================
# DATA STRUCTURES
# ============================================================


@dataclass
class RiskEvidence:
    """
    Explainable evidence supporting a risk score.
    """

    source: str
    indicator: str
    severity: str = "medium"
    score_contribution: float = 0.0
    details: str | None = None


@dataclass
class RiskComponents:
    """
    Normalized component scores.

    Every component must be between 0 and 100.
    """

    rule_score: float = 0.0
    ai_score: float = 0.0
    negative_space_score: float = 0.0
    peer_deviation_score: float = 0.0

    def clamp(self) -> None:
        self.rule_score = clamp_score(self.rule_score)
        self.ai_score = clamp_score(self.ai_score)
        self.negative_space_score = clamp_score(
            self.negative_space_score
        )
        self.peer_deviation_score = clamp_score(
            self.peer_deviation_score
        )


@dataclass
class RiskResult:
    """
    Final explainable risk result.
    """

    entity_id: str
    risk_score: float
    risk_level: str
    confidence: str

    components: RiskComponents

    evidence: list[RiskEvidence] = field(
        default_factory=list
    )

    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "components": {
                "rule_score": self.components.rule_score,
                "ai_score": self.components.ai_score,
                "negative_space_score": (
                    self.components.negative_space_score
                ),
                "peer_deviation_score": (
                    self.components.peer_deviation_score
                ),
            },
            "evidence": [
                {
                    "source": item.source,
                    "indicator": item.indicator,
                    "severity": item.severity,
                    "score_contribution": (
                        item.score_contribution
                    ),
                    "details": item.details,
                }
                for item in self.evidence
            ],
            "summary": self.summary,
        }


# ============================================================
# HELPERS
# ============================================================


def clamp_score(value: float | int | None) -> float:
    """
    Keep a score inside 0-100.
    """

    if value is None:
        return 0.0

    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    return round(
        max(0.0, min(100.0, value)),
        2,
    )


def calculate_risk_level(score: float) -> str:
    """
    Convert numerical risk into the project-defined level.
    """

    if score > 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"


def calculate_confidence(
    components: RiskComponents,
    evidence_count: int,
) -> str:
    """
    Confidence represents how much analytical evidence
    supports the finding.

    This is NOT the same as risk.

    High confidence:
        multiple analytical layers agree.

    Medium confidence:
        at least one strong layer or multiple signals.

    Low confidence:
        weak / sparse evidence.
    """

    active_components = sum(
        score > 0
        for score in [
            components.rule_score,
            components.ai_score,
            components.negative_space_score,
            components.peer_deviation_score,
        ]
    )

    if active_components >= 3 and evidence_count >= 3:
        return "High"

    if active_components >= 2 or evidence_count >= 2:
        return "Medium"

    return "Low"


# ============================================================
# MAIN ENGINE
# ============================================================


def calculate_risk(
    entity_id: str,
    components: RiskComponents,
    evidence: list[RiskEvidence] | None = None,
) -> RiskResult:
    """
    Calculate final SAT-SA risk.

    Parameters
    ----------
    entity_id:
        Analyst / organization / asset / finding ID.

    components:
        Scores from the individual intelligence layers.

    evidence:
        Explainable reasons supporting those scores.
    """

    components.clamp()

    evidence = evidence or []

    weighted_score = (
        components.rule_score * RULE_WEIGHT
        + components.ai_score * AI_WEIGHT
        + components.negative_space_score
        * NEGATIVE_SPACE_WEIGHT
        + components.peer_deviation_score
        * PEER_WEIGHT
    )

    final_score = round(
        clamp_score(weighted_score),
        2,
    )

    risk_level = calculate_risk_level(
        final_score
    )

    confidence = calculate_confidence(
        components,
        len(evidence),
    )

    summary = build_summary(
        risk_level=risk_level,
        score=final_score,
        evidence=evidence,
    )

    return RiskResult(
        entity_id=entity_id,
        risk_score=final_score,
        risk_level=risk_level,
        confidence=confidence,
        components=components,
        evidence=evidence,
        summary=summary,
    )


# ============================================================
# SUMMARY / EXPLANATION
# ============================================================


def build_summary(
    risk_level: str,
    score: float,
    evidence: list[RiskEvidence],
) -> str:
    """
    Create a short supervisor-friendly explanation.
    """

    if not evidence:
        return (
            f"{risk_level} risk ({score}/100). "
            "No supporting evidence was supplied."
        )

    top_indicators = [
        item.indicator
        for item in evidence[:3]
        if item.indicator
    ]

    if not top_indicators:
        return (
            f"{risk_level} risk ({score}/100)."
        )

    reasons = ", ".join(top_indicators)

    return (
        f"{risk_level} risk ({score}/100) "
        f"driven by {reasons}."
    )


# ============================================================
# CONVENIENCE BUILDER
# ============================================================


def build_components(
    rule_score: float = 0.0,
    ai_score: float = 0.0,
    negative_space_score: float = 0.0,
    peer_deviation_score: float = 0.0,
) -> RiskComponents:
    """
    Convenience function for creating normalized components.
    """

    components = RiskComponents(
        rule_score=rule_score,
        ai_score=ai_score,
        negative_space_score=negative_space_score,
        peer_deviation_score=peer_deviation_score,
    )

    components.clamp()

    return components


# ============================================================
# EXAMPLE
# ============================================================


if __name__ == "__main__":

    components = build_components(
        rule_score=85,
        ai_score=70,
        negative_space_score=40,
        peer_deviation_score=80,
    )

    evidence = [
        RiskEvidence(
            source="rules",
            indicator="Suspiciously fast closure",
            severity="high",
            score_contribution=30,
            details=(
                "Critical alerts were repeatedly "
                "closed in under 10 minutes."
            ),
        ),
        RiskEvidence(
            source="behavior",
            indicator="Low investigation quality",
            severity="high",
            score_contribution=25,
            details=(
                "Investigation activity was shallow "
                "relative to expected behavior."
            ),
        ),
        RiskEvidence(
            source="peer",
            indicator="Peer deviation",
            severity="medium",
            score_contribution=10,
            details=(
                "Observed SOC metric deviates "
                "significantly from peer baseline."
            ),
        ),
    ]

    result = calculate_risk(
        entity_id="AN22005",
        components=components,
        evidence=evidence,
    )

    print("\nSAT-SA RISK ENGINE")
    print("=" * 60)
    print(f"Entity:      {result.entity_id}")
    print(f"Risk Score:  {result.risk_score}/100")
    print(f"Risk Level:  {result.risk_level}")
    print(f"Confidence:  {result.confidence}")
    print()
    print("Components:")
    print(
        f"  Rules:          "
        f"{result.components.rule_score}"
    )
    print(
        f"  AI/Behavior:    "
        f"{result.components.ai_score}"
    )
    print(
        f"  Negative Space: "
        f"{result.components.negative_space_score}"
    )
    print(
        f"  Peer:           "
        f"{result.components.peer_deviation_score}"
    )
    print()
    print("Summary:")
    print(f"  {result.summary}")
    print()
    print("Evidence:")

    for item in result.evidence:
        print(
            f"  [{item.severity.upper()}] "
            f"{item.indicator}"
        )