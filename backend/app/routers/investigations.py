from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.investigation import Investigation
from app.services.pagination import paginate


router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["Investigations"],
)


@router.get("")
def list_investigations(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    analyst_id: str | None = None,
    alert_id: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Investigation)

    if analyst_id:
        query = query.filter(
            Investigation.analyst_id == analyst_id
        )

    if alert_id:
        query = query.filter(
            Investigation.alert_id == alert_id
        )

    result = paginate(
        query.order_by(
            Investigation.started_at.desc()
        ),
        page,
        limit,
    )

    return {
        "success": True,
        **result,
    }


@router.get("/{investigation_id}")
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.investigation_id
            == investigation_id
        )
        .first()
    )

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    return investigation