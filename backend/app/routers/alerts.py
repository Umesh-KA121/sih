from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.schemas import AlertResponse
from app.services.pagination import paginate


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)


@router.get("")
def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    organization_id: str | None = None,
    analyst_id: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if severity:
        query = query.filter(
            Alert.severity == severity
        )

    if status:
        query = query.filter(
            Alert.status == status
        )

    if organization_id:
        query = query.filter(
            Alert.organization_id == organization_id
        )

    if analyst_id:
        query = query.filter(
            Alert.analyst_id == analyst_id
        )

    result = paginate(
        query.order_by(Alert.created_at.desc()),
        page,
        limit,
    )

    return {
        "success": True,
        **result,
    }


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(Alert)
        .filter(Alert.alert_id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert


@router.get("/statistics/summary")
def alert_statistics(
    db: Session = Depends(get_db),
):
    total = db.query(Alert).count()

    open_count = (
        db.query(Alert)
        .filter(Alert.status == "Open")
        .count()
    )

    critical_count = (
        db.query(Alert)
        .filter(Alert.severity == "Critical")
        .count()
    )

    escalated = (
        db.query(Alert)
        .filter(Alert.escalated.is_(True))
        .count()
    )

    evidence_reviewed = (
        db.query(Alert)
        .filter(Alert.evidence_reviewed.is_(True))
        .count()
    )

    return {
        "success": True,
        "total": total,
        "open": open_count,
        "critical": critical_count,
        "escalated": escalated,
        "evidence_reviewed": evidence_reviewed,
        "escalation_rate": (
            round(escalated / total * 100, 2)
            if total else 0
        ),
        "evidence_review_rate": (
            round(
                evidence_reviewed / total * 100,
                2,
            )
            if total else 0
        ),
    }