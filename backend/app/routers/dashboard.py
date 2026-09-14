from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.organization import Organization
from app.models.analyst import Analyst
from app.models.asset import Asset
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.investigation import Investigation


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)


@router.get("/overview")
def dashboard_overview(
    db: Session = Depends(get_db),
):

    total_organizations = (
        db.query(Organization).count()
    )

    total_analysts = (
        db.query(Analyst).count()
    )

    total_assets = (
        db.query(Asset).count()
    )

    total_alerts = (
        db.query(Alert).count()
    )

    total_incidents = (
        db.query(Incident).count()
    )

    total_investigations = (
        db.query(Investigation).count()
    )

    open_alerts = (
        db.query(Alert)
        .filter(Alert.status == "Open")
        .count()
    )

    critical_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "Critical")
        .count()
    )

    return {
        "success": True,
        "data": {
            "total_organizations":
                total_organizations,
            "total_analysts":
                total_analysts,
            "total_assets":
                total_assets,
            "total_alerts":
                total_alerts,
            "total_incidents":
                total_incidents,
            "total_investigations":
                total_investigations,
            "open_alerts":
                open_alerts,
            "critical_alerts":
                critical_alerts,
        },
    }


@router.get("/risk-summary")
def risk_summary(
    db: Session = Depends(get_db),
):

    total = db.query(Alert).count()

    critical = (
        db.query(Alert)
        .filter(Alert.severity == "Critical")
        .count()
    )

    high = (
        db.query(Alert)
        .filter(Alert.severity == "High")
        .count()
    )

    medium = (
        db.query(Alert)
        .filter(Alert.severity == "Medium")
        .count()
    )

    low = (
        db.query(Alert)
        .filter(Alert.severity == "Low")
        .count()
    )

    if total:
        overall = round(
            (
                critical * 100
                + high * 75
                + medium * 50
                + low * 25
            ) / total,
            2,
        )
    else:
        overall = 0

    if overall >= 80:
        severity = "CRITICAL"
    elif overall >= 60:
        severity = "HIGH"
    elif overall >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "success": True,
        "data": {
            "overall_risk_score": overall,
            "severity": severity,
            "critical_alerts": critical,
            "high_alerts": high,
            "medium_alerts": medium,
            "low_alerts": low,
        },
    }


@router.get("/trends")
def dashboard_trends(
    db: Session = Depends(get_db),
):

    rows = (
        db.query(
            Alert.severity,
            Alert.status,
        )
        .all()
    )

    distribution = {}

    for severity, status in rows:

        if severity not in distribution:
            distribution[severity] = {}

        distribution[severity][status] = (
            distribution[severity].get(status, 0)
            + 1
        )

    return {
        "success": True,
        "data": distribution,
    }