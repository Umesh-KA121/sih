from app.services.findings.finding_engine import FindingEngine


def main():

    engine = FindingEngine()

    findings = engine.generate(
        analysts=[
            {
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
            },
            {
                "analyst_id": "AN00007",
                "organization_id": "ORG00001",
                "name": "Simran Verma",
                "risk_score": 85,
                "indicators": [
                    "Suspiciously fast closure",
                    "Low evidence-review rate",
                    "Shallow investigation activity",
                ],
            },
        ]
    )

    print()
    print("=" * 70)
    print("SAT-SA FINDING INTELLIGENCE")
    print("=" * 70)

    for finding in findings:

        print()
        print(
            f"{finding.finding_id}"
        )

        print(
            f"Severity: {finding.severity}"
        )

        print(
            f"Risk: {finding.risk_score}/100"
        )

        print(
            f"Confidence: {finding.confidence:.1f}%"
        )

        print(
            f"Category: {finding.category}"
        )

        print(
            f"Title: {finding.title}"
        )

        print("Indicators:")

        for indicator in finding.indicators:
            print(f"  - {indicator}")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    summary = engine.summary()

    for key, value in summary.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()