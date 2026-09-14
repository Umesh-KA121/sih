from collections import Counter

from sqlalchemy import Boolean, Integer, func

from app.database import SessionLocal
from app.models import Alert, Investigation


def percentile(values, p):
    if not values:
        return 0

    values = sorted(values)
    index = int((len(values) - 1) * p)
    return values[index]


def main():
    db = SessionLocal()

    try:
        # ---------------------------------------------------------
        # Alert-level metrics
        # ---------------------------------------------------------
        alert_rows = (
            db.query(
                Alert.analyst_id,
                func.count(Alert.alert_id).label("total_alerts"),
                func.avg(Alert.closure_time_minutes).label("avg_closure"),
            )
            .group_by(Alert.analyst_id)
            .all()
        )

        closure_times = []
        alert_counts = []

        evidence_rates = []
        escalation_rates = []

        for row in alert_rows:
            alert_counts.append(row.total_alerts)

            if row.avg_closure is not None:
                closure_times.append(float(row.avg_closure))

        # Separate query for boolean behavior
        behavior_rows = (
            db.query(
                Alert.analyst_id,
                func.count(Alert.alert_id).label("total"),
                func.sum(
                    func.cast(Alert.evidence_reviewed, Integer)
                ).label("evidence"),
                func.sum(
                    func.cast(Alert.escalated, Integer)
                ).label("escalated"),
            )
            .group_by(Alert.analyst_id)
            .all()
        )

        for row in behavior_rows:
            total = row.total or 0

            if total:
                evidence_rates.append(
                    ((row.evidence or 0) / total) * 100
                )

                escalation_rates.append(
                    ((row.escalated or 0) / total) * 100
                )

        # ---------------------------------------------------------
        # Investigation metrics
        # ---------------------------------------------------------
        investigation_rows = (
            db.query(
                Investigation.analyst_id,
                func.count(Investigation.investigation_id).label("total"),
                func.avg(Investigation.duration_minutes).label("avg_duration"),
            )
            .group_by(Investigation.analyst_id)
            .all()
        )

        investigation_counts = []
        investigation_durations = []

        for row in investigation_rows:
            investigation_counts.append(row.total or 0)

            if row.avg_duration is not None:
                investigation_durations.append(float(row.avg_duration))

        # ---------------------------------------------------------
        # Output
        # ---------------------------------------------------------
        print()
        print("SAT-SA ANALYST METRIC DISTRIBUTION")
        print("=" * 70)

        print("\nALERT WORKLOAD")
        print("-" * 70)
        print(f"Analysts with alerts: {len(alert_counts)}")
        print(f"Min alerts:           {min(alert_counts) if alert_counts else 0}")
        print(f"Median alerts:        {percentile(alert_counts, 0.50)}")
        print(f"90th percentile:      {percentile(alert_counts, 0.90)}")
        print(f"95th percentile:      {percentile(alert_counts, 0.95)}")
        print(f"Max alerts:           {max(alert_counts) if alert_counts else 0}")

        print("\nAVERAGE CLOSURE TIME")
        print("-" * 70)
        print(f"Min:                  {min(closure_times) if closure_times else 0:.2f} min")
        print(f"Median:               {percentile(closure_times, 0.50):.2f} min")
        print(f"90th percentile:      {percentile(closure_times, 0.90):.2f} min")
        print(f"95th percentile:      {percentile(closure_times, 0.95):.2f} min")
        print(f"Max:                  {max(closure_times) if closure_times else 0:.2f} min")

        print("\nEVIDENCE REVIEW RATE")
        print("-" * 70)
        print(f"Min:                  {min(evidence_rates) if evidence_rates else 0:.2f}%")
        print(f"Median:               {percentile(evidence_rates, 0.50):.2f}%")
        print(f"10th percentile:      {percentile(evidence_rates, 0.10):.2f}%")
        print(f"5th percentile:       {percentile(evidence_rates, 0.05):.2f}%")
        print(f"Max:                  {max(evidence_rates) if evidence_rates else 0:.2f}%")

        print("\nESCALATION RATE")
        print("-" * 70)
        print(f"Min:                  {min(escalation_rates) if escalation_rates else 0:.2f}%")
        print(f"Median:               {percentile(escalation_rates, 0.50):.2f}%")
        print(f"90th percentile:      {percentile(escalation_rates, 0.90):.2f}%")
        print(f"95th percentile:      {percentile(escalation_rates, 0.95):.2f}%")
        print(f"Max:                  {max(escalation_rates) if escalation_rates else 0:.2f}%")

        print("\nINVESTIGATION COUNT")
        print("-" * 70)
        print(f"Analysts with investigations: {len(investigation_counts)}")
        print(f"Min:                          {min(investigation_counts) if investigation_counts else 0}")
        print(f"Median:                       {percentile(investigation_counts, 0.50)}")
        print(f"90th percentile:              {percentile(investigation_counts, 0.90)}")
        print(f"95th percentile:              {percentile(investigation_counts, 0.95)}")
        print(f"Max:                          {max(investigation_counts) if investigation_counts else 0}")

        print("\nAVERAGE INVESTIGATION DURATION")
        print("-" * 70)
        print(
            f"Min:                  "
            f"{min(investigation_durations) if investigation_durations else 0:.2f} min"
        )
        print(
            f"Median:               "
            f"{percentile(investigation_durations, 0.50):.2f} min"
        )
        print(
            f"90th percentile:      "
            f"{percentile(investigation_durations, 0.90):.2f} min"
        )
        print(
            f"95th percentile:      "
            f"{percentile(investigation_durations, 0.95):.2f} min"
        )
        print(
            f"Max:                  "
            f"{max(investigation_durations) if investigation_durations else 0:.2f} min"
        )

        print()
        print("=" * 70)

    finally:
        db.close()


if __name__ == "__main__":
    main()