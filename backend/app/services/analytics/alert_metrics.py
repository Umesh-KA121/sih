from sqlalchemy import func

from app.database import SessionLocal
from app.models.alert import Alert
from app.models.investigation import Investigation


def get_alert_metrics() -> dict:
    db = SessionLocal()

    try:
        # ---------------------------------------------------------
        # Basic alert counts
        # ---------------------------------------------------------

        total_alerts = db.query(func.count(Alert.alert_id)).scalar() or 0

        critical_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.severity == "Critical")
            .scalar()
            or 0
        )

        high_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.severity == "High")
            .scalar()
            or 0
        )

        medium_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.severity == "Medium")
            .scalar()
            or 0
        )

        low_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.severity == "Low")
            .scalar()
            or 0
        )

        # ---------------------------------------------------------
        # Status counts
        # ---------------------------------------------------------

        open_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.status == "Open")
            .scalar()
            or 0
        )

        investigating_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.status == "Investigating")
            .scalar()
            or 0
        )

        escalated_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.status == "Escalated")
            .scalar()
            or 0
        )

        closed_alerts = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.status == "Closed")
            .scalar()
            or 0
        )

        # ---------------------------------------------------------
        # Evidence / escalation / false-positive metrics
        # ---------------------------------------------------------

        evidence_reviewed = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.evidence_reviewed.is_(True))
            .scalar()
            or 0
        )

        escalated_flagged = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.escalated.is_(True))
            .scalar()
            or 0
        )

        false_positives = (
            db.query(func.count(Alert.alert_id))
            .filter(Alert.false_positive.is_(True))
            .scalar()
            or 0
        )

        # ---------------------------------------------------------
        # Average closure time
        # ---------------------------------------------------------

        avg_closure_time = (
            db.query(func.avg(Alert.closure_time_minutes))
            .filter(Alert.closure_time_minutes.isnot(None))
            .scalar()
        )

        # ---------------------------------------------------------
        # Investigation metrics
        # ---------------------------------------------------------

        total_investigations = (
            db.query(func.count(Investigation.investigation_id)).scalar() or 0
        )

        avg_investigation_time = (
            db.query(func.avg(Investigation.duration_minutes))
            .filter(Investigation.duration_minutes.isnot(None))
            .scalar()
        )

        # ---------------------------------------------------------
        # Rates
        # ---------------------------------------------------------

        if total_alerts:
            evidence_review_rate = round(
                (evidence_reviewed / total_alerts) * 100, 2
            )

            escalation_rate = round(
                (escalated_flagged / total_alerts) * 100, 2
            )

            false_positive_rate = round(
                (false_positives / total_alerts) * 100, 2
            )

            closure_rate = round(
                (closed_alerts / total_alerts) * 100, 2
            )
        else:
            evidence_review_rate = 0.0
            escalation_rate = 0.0
            false_positive_rate = 0.0
            closure_rate = 0.0

        # ---------------------------------------------------------
        # Return intelligence summary
        # ---------------------------------------------------------

        return {
            "total_alerts": total_alerts,

            "severity": {
                "critical": critical_alerts,
                "high": high_alerts,
                "medium": medium_alerts,
                "low": low_alerts,
            },

            "status": {
                "open": open_alerts,
                "investigating": investigating_alerts,
                "escalated": escalated_alerts,
                "closed": closed_alerts,
            },

            "quality": {
                "evidence_reviewed": evidence_reviewed,
                "false_positives": false_positives,
                "escalated": escalated_flagged,
            },

            "rates": {
                "evidence_review_rate": evidence_review_rate,
                "false_positive_rate": false_positive_rate,
                "escalation_rate": escalation_rate,
                "closure_rate": closure_rate,
            },

            "performance": {
                "average_closure_time_minutes": (
                    round(float(avg_closure_time), 2)
                    if avg_closure_time is not None
                    else 0.0
                ),
                "average_investigation_time_minutes": (
                    round(float(avg_investigation_time), 2)
                    if avg_investigation_time is not None
                    else 0.0
                ),
            },

            "investigations": {
                "total": total_investigations,
            },
        }
    except Exception as exc:
        raise RuntimeError(
            f"Failed to calculate alert metrics: {exc}"
        ) from exc
    finally:
        db.close()


if __name__ == "__main__":
    metrics = get_alert_metrics()

    print("\nSAT-SA ALERT INTELLIGENCE")
    print("=" * 40)

    print(f"Total alerts: {metrics['total_alerts']}")

    print("\nSeverity")
    print(f"  Critical: {metrics['severity']['critical']}")
    print(f"  High:     {metrics['severity']['high']}")
    print(f"  Medium:   {metrics['severity']['medium']}")
    print(f"  Low:      {metrics['severity']['low']}")

    print("\nStatus")
    print(f"  Open:          {metrics['status']['open']}")
    print(f"  Investigating: {metrics['status']['investigating']}")
    print(f"  Escalated:     {metrics['status']['escalated']}")
    print(f"  Closed:        {metrics['status']['closed']}")

    print("\nQuality")
    print(f"  Evidence reviewed: {metrics['quality']['evidence_reviewed']}")
    print(f"  False positives:   {metrics['quality']['false_positives']}")
    print(f"  Escalated:         {metrics['quality']['escalated']}")

    print("\nRates")
    print(f"  Evidence review: {metrics['rates']['evidence_review_rate']}%")
    print(f"  False positive:  {metrics['rates']['false_positive_rate']}%")
    print(f"  Escalation:      {metrics['rates']['escalation_rate']}%")
    print(f"  Closure:         {metrics['rates']['closure_rate']}%")

    print("\nPerformance")
    print(
        f"  Avg closure time: "
        f"{metrics['performance']['average_closure_time_minutes']} minutes"
    )
    print(
        f"  Avg investigation time: "
        f"{metrics['performance']['average_investigation_time_minutes']} minutes"
    )

    print(
        f"\nTotal investigations: "
        f"{metrics['investigations']['total']}"
    )