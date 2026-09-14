from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.analyst import Analyst
from app.models.alert import Alert
from app.services.pagination import paginate


router = APIRouter(
    prefix="/api/v1/analysts",
    tags=["Analysts"],
)


@router.get("")
def list_analysts(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    organization_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Analyst)

    if organization_id:
        query = query.filter(
            Analyst.organization_id == organization_id
        )

    if status:
        query = query.filter(
            Analyst.status == status
        )

    result = paginate(
        query.order_by(Analyst.analyst_id),
        page,
        limit,
    )

    return {
        "success": True,
        **result,
    }


@router.get("/suspicious")
def suspicious_analysts(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """
    Lightweight suspicious-analyst endpoint.

    The full analyst intelligence remains in
    analyst_metrics.py and will be connected more deeply
    during the integration pass.
    """

    analysts = (
        db.query(Analyst)
        .join(
            Alert,
            Alert.analyst_id == Analyst.analyst_id,
        )
        .filter(
            Alert.closure_time_minutes <= 10
        )
        .group_by(Analyst.analyst_id)
        .limit(limit)
        .all()
    )

    return {
        "success": True,
        "count": len(analysts),
        "data": analysts,
    }


@router.get("/{analyst_id}")
def get_analyst(
    analyst_id: str,
    db: Session = Depends(get_db),
):
    analyst = (
        db.query(Analyst)
        .filter(
            Analyst.analyst_id == analyst_id
        )
        .first()
    )

    if not analyst:
        raise HTTPException(
            status_code=404,
            detail="Analyst not found",
        )

    return analyst