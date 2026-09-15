from fastapi import APIRouter, HTTPException

from app.services.intelligence.supervisory_engine import (
    run_supervisory_analysis,
)


router = APIRouter(
    prefix="/api/intelligence",
    tags=["Intelligence"],
)


@router.get("/summary")
def intelligence_summary():

    result = run_supervisory_analysis()

    return {
        "overall_health": result[
            "overall_health"
        ],
        "risk_distribution": result[
            "risk_distribution"
        ],
        "finding_count": result[
            "finding_count"
        ],
        "high_priority_findings": result[
            "high_priority_findings"
        ][:10],
    }


@router.get("/findings")
def intelligence_findings():

    result = run_supervisory_analysis()

    return {
        "count": result[
            "finding_count"
        ],
        "findings": result[
            "findings"
        ],
    }


@router.get("/analysts")
def intelligence_analysts():

    result = run_supervisory_analysis()

    return {
        "count": len(
            result["analysts"]
        ),
        "analysts": result[
            "analysts"
        ],
    }


@router.get("/analysts/{analyst_id}")
def intelligence_analyst(
    analyst_id: str,
):

    result = run_supervisory_analysis()

    for analyst in result[
        "analysts"
    ]:

        if analyst[
            "analyst_id"
        ] == analyst_id:

            return analyst

    raise HTTPException(
        status_code=404,
        detail="Analyst not found",
    )


@router.post("/run")
def run_intelligence():

    result = run_supervisory_analysis()

    return {
        "status": "completed",
        "overall_health": result[
            "overall_health"
        ],
        "finding_count": result[
            "finding_count"
        ],
        "risk_distribution": result[
            "risk_distribution"
        ],
    }