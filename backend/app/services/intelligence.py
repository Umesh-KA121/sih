from app.services.findings.finding_engine import (
    FindingEngine,
)


class IntelligenceService:

    def __init__(self):
        self.finding_engine = FindingEngine()

    def generate_findings(
        self,
        analysts=None,
        alerts=None,
        investigations=None,
    ):

        return self.finding_engine.generate(
            analysts=analysts,
            alerts=alerts,
            investigations=investigations,
        )

    def summary(
        self,
        analysts=None,
        alerts=None,
        investigations=None,
    ):

        self.generate_findings(
            analysts=analysts,
            alerts=alerts,
            investigations=investigations,
        )

        return self.finding_engine.summary()