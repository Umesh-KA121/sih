from __future__ import annotations

from typing import Any

from app.services.intelligence.supervisory_engine import (
    clear_engine_cache,
    get_analyst_finding,
    get_analyst_findings,
    get_findings,
    get_summary,
    run_supervisory_analysis,
)


def get_engine_summary(
    force_refresh: bool = False,
) -> dict[str, Any]:
    result = run_supervisory_analysis(
        force_refresh=force_refresh,
    )

    return {
        "engine_version": result.get(
            "engine_version",
            "unknown",
        ),
        "generated_at": result.get(
            "generated_at",
        ),
        "summary": get_summary(
            result=result,
        ),
    }


def get_all_findings(
    force_refresh: bool = False,
) -> list[dict[str, Any]]:
    result = run_supervisory_analysis(
        force_refresh=force_refresh,
    )

    return get_findings(
        result=result,
    )


def get_findings_for_analyst(
    analyst_id: str,
    force_refresh: bool = False,
) -> list[dict[str, Any]]:
    result = run_supervisory_analysis(
        force_refresh=force_refresh,
    )

    return get_analyst_findings(
        result=result,
        analyst_id=analyst_id,
    )


def get_single_analyst_finding(
    analyst_id: str,
    force_refresh: bool = False,
) -> dict[str, Any] | None:
    result = run_supervisory_analysis(
        force_refresh=force_refresh,
    )

    return get_analyst_finding(
        result=result,
        analyst_id=analyst_id,
    )


def refresh_engine() -> dict[str, Any]:
    result = run_supervisory_analysis(
        force_refresh=True,
    )

    return {
        "status": "refreshed",
        "engine_version": result.get(
            "engine_version",
        ),
        "generated_at": result.get(
            "generated_at",
        ),
    }


def clear_cache() -> dict[str, str]:
    clear_engine_cache()

    return {
        "status": "cache_cleared",
    }