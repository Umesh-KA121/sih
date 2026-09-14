from fastapi import APIRouter, Query

from app.services.findings.finding_engine import (
    FindingEngine,
)


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


# ------------------------------------------------------------
# Temporary in-memory finding provider
# ------------------------------------------------------------
#
# During the integration pass this will be replaced by
# database-backed finding generation/cache.
# ------------------------------------------------------------

def build_demo_findings():

    engine = FindingEngine()

    return engine.generate(
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


@router.get("")
def list_findings(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    severity: str | None = None,
    category: str | None = None,
):

    engine = FindingEngine()

    findings = build_demo_findings()

    if severity:
        findings = [
            finding
            for finding in findings
            if finding.severity
            == severity.upper()
        ]

    if category:
        findings = [
            finding
            for finding in findings
            if finding.category
            == category.upper()
        ]

    total = len(findings)

    start = (page - 1) * limit
    end = start + limit

    data = findings[start:end]

    return {
        "success": True,
        "total": total,
        "page": page,
        "limit": limit,
        "data": [
            finding.to_dict()
            for finding in data
        ],
    }


@router.get("/summary")
def findings_summary():

    engine = FindingEngine()

    engine.generate(
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
                ],
            },
            {
                "analyst_id": "AN00007",
                "organization_id": "ORG00001",
                "name": "Simran Verma",
                "risk_score": 85,
                "indicators": [
                    "Suspiciously fast closure",
                ],
            },
        ]
    )

    return {
        "success": True,
        **engine.summary(),
    }


@router.get("/{finding_id}")
def get_finding(finding_id: str):

    findings = build_demo_findings()

    for finding in findings:

        if finding.finding_id == finding_id:

            return {
                "success": True,
                "data": finding.to_dict(),
            }

    return {
        "success": False,
        "message": "Finding not found",
    }