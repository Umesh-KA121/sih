from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.services.intelligence.api_service import (
    clear_cache,
    get_all_findings,
    get_engine_summary,
    get_findings_for_analyst,
    get_single_analyst_finding,
    refresh_engine,
)

router = APIRouter(
    prefix="/intelligence",
    tags=["Intelligence"],
)


@router.get("/summary")
def intelligence_summary(
    refresh: bool = Query(
        False,
        description="Force a fresh engine calculation.",
    ),
):
    return get_engine_summary(
        force_refresh=refresh,
    )


@router.get("/findings")
def intelligence_findings(
    refresh: bool = Query(
        False,
        description="Force a fresh engine calculation.",
    ),
):
    return {
        "count": len(
            findings := get_all_findings(
                force_refresh=refresh,
            )
        ),
        "findings": findings,
    }


@router.get("/analysts/{analyst_id}")
def intelligence_analyst(
    analyst_id: str,
    refresh: bool = Query(False),
):
    result = get_single_analyst_finding(
        analyst_id=analyst_id,
        force_refresh=refresh,
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Analyst not found.",
        )

    return result


@router.get("/analysts/{analyst_id}/findings")
def intelligence_analyst_findings(
    analyst_id: str,
    refresh: bool = Query(False),
):
    findings = get_findings_for_analyst(
        analyst_id=analyst_id,
        force_refresh=refresh,
    )

    return {
        "analyst_id": analyst_id,
        "count": len(findings),
        "findings": findings,
    }


@router.post("/refresh")
def intelligence_refresh():
    return refresh_engine()


@router.post("/clear-cache")
def intelligence_clear_cache():
    return clear_cache()