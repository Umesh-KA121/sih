from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.services.intelligence.supervisory_engine import (
    run_supervisory_analysis,
)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/overview")
def dashboard_overview() -> dict[str, Any]:
    result = run_supervisory_analysis()

    findings = result.get(
        "findings",
        [],
    )

    summary = result.get(
        "summary",
        {},
    )

    risk_distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for finding in findings:
        level = str(
            finding.get("risk_level", "LOW")
        ).upper()

        if level in risk_distribution:
            risk_distribution[level] += 1

    return {
        "summary": summary,
        "risk_distribution": risk_distribution,
        "finding_count": len(findings),
        "engine_version": result.get(
            "engine_version",
        ),
        "generated_at": result.get(
            "generated_at",
        ),
    }