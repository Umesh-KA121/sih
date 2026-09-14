"""
SAT-SA Risk Engine

Provides a common scoring mechanism for:
- Analysts
- Alerts
- Investigations
- Assets
- Findings
- Organizations
"""

from dataclasses import dataclass


@dataclass
class RiskResult:
    score: float
    severity: str
    factors: list[str]


class RiskEngine:
    """
    Centralized SAT-SA risk calculation engine.
    """

    @staticmethod
    def clamp(score: float) -> float:
        return round(
            max(0.0, min(100.0, score)),
            2,
        )

    @staticmethod
    def severity(score: float) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # Weighted Score
    # =========================================================

    def weighted_score(
        self,
        *,
        base_score: float = 0,
        evidence_risk: float = 0,
        investigation_risk: float = 0,
        escalation_risk: float = 0,
        behavior_risk: float = 0,
        asset_risk: float = 0,
        benchmark_risk: float = 0,
    ) -> RiskResult:

        factors: list[str] = []

        score = (
            base_score * 0.20
            + evidence_risk * 0.15
            + investigation_risk * 0.15
            + escalation_risk * 0.10
            + behavior_risk * 0.15
            + asset_risk * 0.15
            + benchmark_risk * 0.10
        )

        score = self.clamp(score)

        values = {
            "Evidence risk": evidence_risk,
            "Investigation risk": investigation_risk,
            "Escalation risk": escalation_risk,
            "Behavior risk": behavior_risk,
            "Asset risk": asset_risk,
            "Benchmark risk": benchmark_risk,
        }

        for name, value in values.items():

            if value >= 60:
                factors.append(
                    f"{name}: {value:.1f}"
                )

        return RiskResult(
            score=score,
            severity=self.severity(score),
            factors=factors,
        )

    # =========================================================
    # Analyst Risk
    # =========================================================

    def analyst_risk(
        self,
        *,
        closure_risk: float = 0,
        evidence_review_risk: float = 0,
        escalation_risk: float = 0,
        investigation_risk: float = 0,
    ) -> RiskResult:

        score = (
            closure_risk * 0.30
            + evidence_review_risk * 0.30
            + escalation_risk * 0.15
            + investigation_risk * 0.25
        )

        score = self.clamp(score)

        factors = []

        if closure_risk >= 60:
            factors.append(
                "Suspicious closure behavior"
            )

        if evidence_review_risk >= 60:
            factors.append(
                "Low evidence-review behavior"
            )

        if escalation_risk >= 60:
            factors.append(
                "Potential escalation deficiency"
            )

        if investigation_risk >= 60:
            factors.append(
                "Investigation quality concern"
            )

        return RiskResult(
            score=score,
            severity=self.severity(score),
            factors=factors,
        )

    # =========================================================
    # Alert Risk
    # =========================================================

    def alert_risk(
        self,
        *,
        severity_risk: float = 0,
        closure_risk: float = 0,
        evidence_risk: float = 0,
        escalation_risk: float = 0,
        false_positive_risk: float = 0,
    ) -> RiskResult:

        score = (
            severity_risk * 0.30
            + closure_risk * 0.20
            + evidence_risk * 0.20
            + escalation_risk * 0.20
            + false_positive_risk * 0.10
        )

        score = self.clamp(score)

        factors = []

        if severity_risk >= 70:
            factors.append(
                "High alert severity"
            )

        if closure_risk >= 60:
            factors.append(
                "Potentially abnormal closure"
            )

        if evidence_risk >= 60:
            factors.append(
                "Insufficient evidence review"
            )

        if escalation_risk >= 60:
            factors.append(
                "Escalation concern"
            )

        if false_positive_risk >= 60:
            factors.append(
                "False-positive pattern"
            )

        return RiskResult(
            score=score,
            severity=self.severity(score),
            factors=factors,
        )