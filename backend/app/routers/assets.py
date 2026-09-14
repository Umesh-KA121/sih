from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.alert import Alert
from app.services.pagination import paginate


router = APIRouter(
    prefix="/api/v1/assets",
    tags=["Assets"],
)


@router.get("")
def list_assets(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    organization_id: str | None = None,
    criticality: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Asset)

    if organization_id:
        query = query.filter(
            Asset.organization_id == organization_id
        )

    if criticality:
        query = query.filter(
            Asset.criticality == criticality
        )

    if status:
        query = query.filter(
            Asset.status == status
        )

    result = paginate(
        query.order_by(Asset.asset_id),
        page,
        limit,
    )

    return {
        "success": True,
        **result,
    }


@router.get("/silent")
def silent_assets(
    db: Session = Depends(get_db),
):
    """
    MVP negative-space signal:
    assets without associated alerts.
    """

    assets_with_alerts = (
        db.query(Alert.asset_id)
        .filter(Alert.asset_id.isnot(None))
        .distinct()
        .subquery()
    )

    assets = (
        db.query(Asset)
        .filter(
            ~Asset.asset_id.in_(
                assets_with_alerts
            )
        )
        .limit(100)
        .all()
    )

    return {
        "success": True,
        "count": len(assets),
        "data": assets,
    }


@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.asset_id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    return asset