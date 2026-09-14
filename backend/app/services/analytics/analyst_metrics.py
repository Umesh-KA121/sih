from collections import defaultdict

from sqlalchemy import case, func

from app.database import SessionLocal
from app.models.analyst import Analyst
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.services.rules.analyst_rules import evaluate_analyst_behavior


def get_analyst_metrics() -> list[dict]:
    """
    Generate intelligence metrics for all analysts.

    Uses grouped SQL aggregation to avoid the N+1 query problem.
    """

    db = SessionLocal()

    try:
        # ==========================================================
        # 1. Load analysts
        # ==========================================================

        analysts = db.query(Analyst).all()

        # ==========================================================
        # 2. Aggregate ALL alert metrics in one SQL query
        # ==========================================================

        alert_rows = (
            db.query(
                Alert.analyst_id.label("analyst_id"),

                func.count(Alert.alert_id).label(
                    "total_alerts"
                ),

                func.sum(
                    case(
                        (Alert.status == "Closed", 1),
                        else_=0,
                    )
                ).label("closed_alerts"),

                func.sum(
                    case(
                        (Alert.status == "Open", 1),
                        else_=0,
                    )
                ).label("open_alerts"),

                func.sum(
                    case(
                        (Alert.status == "Investigating", 1),
                        else_=0,
                    )
                ).label("investigating_alerts"),

                func.sum(
                    case(
                        (Alert.escalated.is_(True), 1),
                        else_=0,
                    )
                ).label("escalated_alerts"),

                func.sum(
                    case(
                        (Alert.false_positive.is_(True), 1),
                        else_=0,
                    )
                ).label("false_positives"),

                func.sum(
                    case(
                        (Alert.evidence_reviewed.is_(True), 1),
                        else_=0,
                    )
                ).label("evidence_reviewed_alerts"),

                func.avg(
                    Alert.closure_time_minutes
                ).label("avg_closure_time"),
            )
            .group_by(Alert.analyst_id)
            .all()
        )

        alert_metrics = {}

        for row in alert_rows:
            alert_metrics[row.analyst_id] = {
                "total_alerts": int(row.total_alerts or 0),
                "closed_alerts": int(row.closed_alerts or 0),
                "open_alerts": int(row.open_alerts or 0),
                "investigating_alerts": int(
                    row.investigating_alerts or 0
                ),
                "escalated_alerts": int(
                    row.escalated_alerts or 0
                ),
                "false_positives": int(
                    row.false_positives or 0
                ),
                "evidence_reviewed_alerts": int(
                    row.evidence_reviewed_alerts or 0
                ),
                "avg_closure_time": (
                    float(row.avg_closure_time)
                    if row.avg_closure_time is not None
                    else None
                ),
            }

        # ==========================================================
        # 3. Aggregate investigation metrics in ONE query
        # ==========================================================

        investigation_rows = (
            db.query(
                Investigation.analyst_id.label(
                    "analyst_id"
                ),

                func.count(
                    Investigation.investigation_id
                ).label("total_investigations"),

                func.avg(
                    Investigation.duration_minutes
                ).label("avg_investigation_time"),

                func.sum(
                    case(
                        (
                            Investigation.evidence_reviewed.is_(True),
                            1,
                        ),
                        else_=0,
                    )
                ).label(
                    "evidence_reviewed_investigations"
                ),

                func.sum(
                    case(
                        (
                            Investigation.escalation_decision
                            == "Yes",
                            1,
                        ),
                        else_=0,
                    )
                ).label(
                    "escalated_investigations"
                ),
            )
            .group_by(Investigation.analyst_id)
            .all()
        )

        investigation_metrics = {}

        for row in investigation_rows:
            investigation_metrics[row.analyst_id] = {
                "total_investigations": int(
                    row.total_investigations or 0
                ),
                "avg_investigation_time": (
                    float(row.avg_investigation_time)
                    if row.avg_investigation_time is not None
                    else None
                ),
                "evidence_reviewed_investigations": int(
                    row.evidence_reviewed_investigations or 0
                ),
                "escalated_investigations": int(
                    row.escalated_investigations or 0
                ),
            }

        # ==========================================================
        # 4. Load investigation activity ONCE
        #
        # actions_performed = descriptive TEXT
        # queries_executed = numeric
        # ==========================================================

        investigation_activity = (
            db.query(
                Investigation.analyst_id,
                Investigation.actions_performed,
                Investigation.queries_executed,
            )
            .all()
        )

        action_totals = defaultdict(int)
        action_records = defaultdict(int)

        query_totals = defaultdict(int)
        query_records = defaultdict(int)

        for investigation in investigation_activity:
            analyst_id = investigation.analyst_id

            # ------------------------------------------------------
            # Actions
            # ------------------------------------------------------

            if investigation.actions_performed:
                actions = [
                    action.strip()
                    for action in str(
                        investigation.actions_performed
                    ).split(";")
                    if action.strip()
                ]

                if actions:
                    action_totals[analyst_id] += len(actions)
                    action_records[analyst_id] += 1

            # ------------------------------------------------------
            # Queries
            # ------------------------------------------------------

            if investigation.queries_executed is not None:
                try:
                    query_value = int(
                        investigation.queries_executed
                    )

                    query_totals[analyst_id] += query_value
                    query_records[analyst_id] += 1

                except (TypeError, ValueError):
                    # Ignore malformed values.
                    pass

        # ==========================================================
        # 5. Build analyst intelligence
        # ==========================================================

        results = []

        for analyst in analysts:
            analyst_id = analyst.analyst_id

            # ------------------------------------------------------
            # Alert metrics
            # ------------------------------------------------------

            alerts = alert_metrics.get(
                analyst_id,
                {
                    "total_alerts": 0,
                    "closed_alerts": 0,
                    "open_alerts": 0,
                    "investigating_alerts": 0,
                    "escalated_alerts": 0,
                    "false_positives": 0,
                    "evidence_reviewed_alerts": 0,
                    "avg_closure_time": None,
                },
            )

            total_alerts = alerts["total_alerts"]
            closed_alerts = alerts["closed_alerts"]
            open_alerts = alerts["open_alerts"]
            investigating_alerts = alerts[
                "investigating_alerts"
            ]
            escalated_alerts = alerts[
                "escalated_alerts"
            ]
            false_positives = alerts[
                "false_positives"
            ]
            evidence_reviewed_alerts = alerts[
                "evidence_reviewed_alerts"
            ]
            avg_closure_time = alerts[
                "avg_closure_time"
            ]

            # ------------------------------------------------------
            # Investigation metrics
            # ------------------------------------------------------

            investigations = investigation_metrics.get(
                analyst_id,
                {
                    "total_investigations": 0,
                    "avg_investigation_time": None,
                    "evidence_reviewed_investigations": 0,
                    "escalated_investigations": 0,
                },
            )

            total_investigations = investigations[
                "total_investigations"
            ]

            avg_investigation_time = investigations[
                "avg_investigation_time"
            ]

            evidence_reviewed_investigations = investigations[
                "evidence_reviewed_investigations"
            ]

            escalated_investigations = investigations[
                "escalated_investigations"
            ]

            # ------------------------------------------------------
            # Average actions
            # ------------------------------------------------------

            if action_records[analyst_id] > 0:
                avg_actions = (
                    action_totals[analyst_id]
                    / action_records[analyst_id]
                )
            else:
                avg_actions = 0.0

            # ------------------------------------------------------
            # Average queries
            # ------------------------------------------------------

            if query_records[analyst_id] > 0:
                avg_queries = (
                    query_totals[analyst_id]
                    / query_records[analyst_id]
                )
            else:
                avg_queries = 0.0

            # ======================================================
            # 6. Calculate rates
            # ======================================================

            if total_alerts > 0:
                closure_rate = round(
                    closed_alerts
                    / total_alerts
                    * 100,
                    2,
                )

                escalation_rate = round(
                    escalated_alerts
                    / total_alerts
                    * 100,
                    2,
                )

                false_positive_rate = round(
                    false_positives
                    / total_alerts
                    * 100,
                    2,
                )

                evidence_review_rate = round(
                    evidence_reviewed_alerts
                    / total_alerts
                    * 100,
                    2,
                )

            else:
                closure_rate = 0.0
                escalation_rate = 0.0
                false_positive_rate = 0.0
                evidence_review_rate = 0.0

            # ------------------------------------------------------
            # Investigation rates
            # ------------------------------------------------------

            if total_investigations > 0:
                investigation_evidence_rate = round(
                    evidence_reviewed_investigations
                    / total_investigations
                    * 100,
                    2,
                )

                investigation_escalation_rate = round(
                    escalated_investigations
                    / total_investigations
                    * 100,
                    2,
                )

            else:
                investigation_evidence_rate = 0.0
                investigation_escalation_rate = 0.0

            # ======================================================
            # 7. Rule-based behavioral intelligence
            # ======================================================

            risk = evaluate_analyst_behavior(
                total_alerts=total_alerts,
                closed_alerts=closed_alerts,
                avg_closure_time=avg_closure_time,
                evidence_review_rate=evidence_review_rate,
                escalation_rate=escalation_rate,
                total_investigations=total_investigations,
                avg_queries=avg_queries,
                avg_investigation_time=avg_investigation_time,
            )

            risk_score = risk["score"]
            risk_level = risk["level"]
            confidence = risk["confidence"]
            indicators = risk["indicators"]

            # ======================================================
            # 9. Store result
            # ======================================================

            results.append(
                {
                    "analyst_id": analyst.analyst_id,
                    "name": analyst.name,
                    "organization_id": analyst.organization_id,
                    "role": analyst.role,
                    "team": analyst.team,
                    "experience_years": analyst.experience_years,
                    "shift": analyst.shift,
                    "status": analyst.status,
                    "confidence": confidence,
                    "alerts": {
                        "total": total_alerts,
                        "closed": closed_alerts,
                        "open": open_alerts,
                        "investigating": investigating_alerts,
                        "escalated": escalated_alerts,
                        "false_positives": false_positives,
                    },
                    "performance": {
                        "average_closure_time_minutes": (
                            round(
                                float(avg_closure_time),
                                2,
                            )
                            if avg_closure_time is not None
                            else 0.0
                        ),
                        "closure_rate": closure_rate,
                        "escalation_rate": escalation_rate,
                        "false_positive_rate": false_positive_rate,
                        "evidence_review_rate": evidence_review_rate,
                    },
                    "investigations": {
                        "total": total_investigations,
                        "average_duration_minutes": (
                            round(
                                float(
                                    avg_investigation_time
                                ),
                                2,
                            )
                            if avg_investigation_time is not None
                            else 0.0
                        ),
                        "average_queries": round(
                            avg_queries,
                            2,
                        ),
                        "average_actions": round(
                            avg_actions,
                            2,
                        ),
                        "evidence_review_rate": (
                            investigation_evidence_rate
                        ),
                        "escalation_rate": (
                            investigation_escalation_rate
                        ),
                    },
                    "risk": {
                        "score": risk_score,
                        "level": risk_level,
                        "indicators": indicators,
                    },
                }
            )

        return results

    finally:
        db.close()


# ==============================================================
# CLI
# ==============================================================

if __name__ == "__main__":
    metrics = get_analyst_metrics()

    print("\nSAT-SA ANALYST INTELLIGENCE")
    print("=" * 70)

    print(
        f"Analysts analyzed: {len(metrics)}"
    )

    suspicious = [
        analyst
        for analyst in metrics
        if analyst["risk"]["score"] >= 40
    ]

    print(
        f"Analysts requiring attention: "
        f"{len(suspicious)}"
    )

    print("\nTop suspicious analysts:")

    for analyst in sorted(
        suspicious,
        key=lambda item: item["risk"]["score"],
        reverse=True,
    )[:10]:

        print(
            f"\n{analyst['analyst_id']} - "
            f"{analyst['name']}"
        )

        print(
            f"  Risk: "
            f"{analyst['risk']['score']}/100 "
            f"({analyst['risk']['level']})"
        )

        print(
            f"  Alerts: "
            f"{analyst['alerts']['total']}"
        )

        print(
            f"  Avg closure: "
            f"{analyst['performance']['average_closure_time_minutes']} min"
        )

        print(
            f"  Evidence review: "
            f"{analyst['performance']['evidence_review_rate']}%"
        )

        print(
            f"  Indicators: "
            f"{', '.join(analyst['risk']['indicators'])}"
        )