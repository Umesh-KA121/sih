"""
SAT-SA Finding Engine

Converts analytical signals into structured security findings.

The engine is intentionally deterministic and explainable.
ML/NLP/Agentic AI can later contribute additional signals,
but the core finding generation remains auditable.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    organization_id: str
    category: str
    severity: str
    title: str
    description: str
    affected_entity: str
    affected_entity_id: str
    risk_score: float
    confidence: float

    evidence: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)

    status: str = "OPEN"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingEngine:
    """
    Central finding-generation engine.

    Supported sources:
    - Analyst analytics
    - Alert analytics
    - Investigation analytics
    - Negative-space analysis
    - Future ML/NLP signals
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    # =========================================================
    # Utility
    # =========================================================

    @staticmethod
    def clamp_score(score: float) -> float:
        return round(max(0.0, min(100.0, score)), 2)

    @staticmethod
    def severity_from_score(score: float) -> str:
        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def confidence_from_indicators(
        indicator_count: int,
        base: float = 60.0,
        increment: float = 8.0,
    ) -> float:
        return min(
            100.0,
            base + (indicator_count * increment),
        )

    # =========================================================
    # Analyst Analysis
    # =========================================================

    def analyze_analyst(
        self,
        analyst: dict[str, Any],
    ) -> Finding | None:

        risk_score = self.clamp_score(
            float(analyst.get("risk_score", 0))
        )

        indicators = [
            str(item)
            for item in analyst.get("indicators", [])
        ]

        if risk_score < 60 and not indicators:
            return None

        analyst_id = str(
            analyst.get("analyst_id", "UNKNOWN")
        )

        organization_id = str(
            analyst.get("organization_id", "UNKNOWN")
        )

        analyst_name = str(
            analyst.get("name", analyst_id)
        )

        severity = self.severity_from_score(risk_score)

        evidence = [
            f"Analyst risk score: {risk_score:.2f}/100"
        ]

        if indicators:
            evidence.append(
                f"{len(indicators)} behavioral indicators detected"
            )

        evidence.extend(indicators)

        return Finding(
            finding_id=f"ANALYST-{analyst_id}",
            organization_id=organization_id,
            category="ANALYST_BEHAVIOR",
            severity=severity,
            title=(
                f"Suspicious analyst behavior: "
                f"{analyst_name}"
            ),
            description=(
                f"Analyst {analyst_name} has generated "
                f"behavioral signals requiring operational "
                f"review. The calculated analyst risk score "
                f"is {risk_score:.2f}/100."
            ),
            affected_entity="ANALYST",
            affected_entity_id=analyst_id,
            risk_score=risk_score,
            confidence=self.confidence_from_indicators(
                len(indicators),
                base=60,
                increment=8,
            ),
            evidence=evidence,
            indicators=indicators,
        )

    # =========================================================
    # Alert Analysis
    # =========================================================

    def analyze_alert(
        self,
        alert: dict[str, Any],
    ) -> Finding | None:

        risk_score = self.clamp_score(
            float(alert.get("risk_score", 0))
        )

        indicators = [
            str(item)
            for item in alert.get("indicators", [])
        ]

        if risk_score < 60 and not indicators:
            return None

        alert_id = str(
            alert.get("alert_id", "UNKNOWN")
        )

        organization_id = str(
            alert.get("organization_id", "UNKNOWN")
        )

        severity = self.severity_from_score(risk_score)

        evidence = [
            f"Alert risk score: {risk_score:.2f}/100"
        ]

        evidence.extend(indicators)

        return Finding(
            finding_id=f"ALERT-{alert_id}",
            organization_id=organization_id,
            category="ALERT_HANDLING",
            severity=severity,
            title=(
                f"High-risk alert requires review: "
                f"{alert_id}"
            ),
            description=(
                f"Alert {alert_id} has generated one or "
                f"more operational risk signals and "
                f"requires supervisor review."
            ),
            affected_entity="ALERT",
            affected_entity_id=alert_id,
            risk_score=risk_score,
            confidence=self.confidence_from_indicators(
                len(indicators),
                base=65,
                increment=7,
            ),
            evidence=evidence,
            indicators=indicators,
        )

    # =========================================================
    # Investigation Analysis
    # =========================================================

    def analyze_investigation(
        self,
        investigation: dict[str, Any],
    ) -> Finding | None:

        risk_score = self.clamp_score(
            float(investigation.get("risk_score", 0))
        )

        indicators = [
            str(item)
            for item in investigation.get("indicators", [])
        ]

        if risk_score < 60 and not indicators:
            return None

        investigation_id = str(
            investigation.get(
                "investigation_id",
                "UNKNOWN",
            )
        )

        organization_id = str(
            investigation.get(
                "organization_id",
                "UNKNOWN",
            )
        )

        severity = self.severity_from_score(risk_score)

        evidence = [
            (
                "Investigation risk score: "
                f"{risk_score:.2f}/100"
            )
        ]

        evidence.extend(indicators)

        return Finding(
            finding_id=(
                f"INVESTIGATION-{investigation_id}"
            ),
            organization_id=organization_id,
            category="INVESTIGATION_QUALITY",
            severity=severity,
            title=(
                "Investigation quality concern: "
                f"{investigation_id}"
            ),
            description=(
                f"Investigation {investigation_id} contains "
                f"signals indicating potentially insufficient "
                f"investigation depth, evidence handling, "
                f"or escalation."
            ),
            affected_entity="INVESTIGATION",
            affected_entity_id=investigation_id,
            risk_score=risk_score,
            confidence=self.confidence_from_indicators(
                len(indicators),
                base=60,
                increment=8,
            ),
            evidence=evidence,
            indicators=indicators,
        )

    # =========================================================
    # Generic Finding
    # =========================================================

    def generate(
        self,
        *,
        analysts: list[dict[str, Any]] | None = None,
        alerts: list[dict[str, Any]] | None = None,
        investigations: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:

        self.findings = []

        for analyst in analysts or []:
            finding = self.analyze_analyst(analyst)

            if finding:
                self.findings.append(finding)

        for alert in alerts or []:
            finding = self.analyze_alert(alert)

            if finding:
                self.findings.append(finding)

        for investigation in investigations or []:
            finding = self.analyze_investigation(
                investigation
            )

            if finding:
                self.findings.append(finding)

        return self.findings

    # =========================================================
    # Query Methods
    # =========================================================

    def get_findings(self) -> list[Finding]:
        return self.findings

    def get_high_risk_findings(
        self,
        threshold: float = 60,
    ) -> list[Finding]:

        return [
            finding
            for finding in self.findings
            if finding.risk_score >= threshold
        ]

    def get_by_severity(
        self,
        severity: str,
    ) -> list[Finding]:

        severity = severity.upper()

        return [
            finding
            for finding in self.findings
            if finding.severity == severity
        ]

    def get_by_category(
        self,
        category: str,
    ) -> list[Finding]:

        category = category.upper()

        return [
            finding
            for finding in self.findings
            if finding.category == category
        ]

    def summary(self) -> dict[str, Any]:

        findings = self.findings

        return {
            "total": len(findings),
            "critical": len(
                self.get_by_severity("CRITICAL")
            ),
            "high": len(
                self.get_by_severity("HIGH")
            ),
            "medium": len(
                self.get_by_severity("MEDIUM")
            ),
            "low": len(
                self.get_by_severity("LOW")
            ),
            "high_risk": len(
                self.get_high_risk_findings()
            ),
        }