from dataclasses import dataclass


@dataclass(frozen=True)
class CSVSchema:
    filename: str
    required_columns: tuple[str, ...]
    id_column: str
    id_prefix: str
    required_non_empty: tuple[str, ...] = ()


CSV_SCHEMAS = {
    "organizations": CSVSchema(
        filename="organizations.csv",
        required_columns=(
            "organization_id",
            "organization_name",
            "industry",
            "organization_size",
            "soc_maturity",
            "region",
            "created_at",
        ),
        id_column="organization_id",
        id_prefix="ORG",
        required_non_empty=(
            "organization_id",
            "organization_name",
        ),
    ),

    "analysts": CSVSchema(
        filename="analysts.csv",
        required_columns=(
            "analyst_id",
            "organization_id",
            "name",
            "role",
            "team",
            "experience_years",
            "shift",
            "status",
            "joined_at",
        ),
        id_column="analyst_id",
        id_prefix="AN",
        required_non_empty=(
            "analyst_id",
            "organization_id",
            "name",
        ),
    ),

    "assets": CSVSchema(
        filename="assets.csv",
        required_columns=(
            "asset_id",
            "organization_id",
            "asset_identifier",
            "asset_name",
            "asset_type",
            "criticality",
            "environment",
            "location",
            "status",
        ),
        id_column="asset_id",
        id_prefix="AST",
        required_non_empty=(
            "asset_id",
            "organization_id",
            "asset_identifier",
            "asset_name",
        ),
    ),

    "alerts": CSVSchema(
        filename="alerts.csv",
        required_columns=(
            "alert_id",
            "external_id",
            "organization_id",
            "asset_id",
            "analyst_id",
            "alert_type",
            "severity",
            "status",
            "created_at",
            "closed_at",
            "closure_time_minutes",
            "investigation_notes",
            "evidence_reviewed",
            "escalated",
            "false_positive",
            "incident_id",
        ),
        id_column="alert_id",
        id_prefix="ALT",
        required_non_empty=(
            "alert_id",
            "external_id",
            "organization_id",
            "asset_id",
            "alert_type",
            "severity",
            "status",
            "created_at",
        ),
    ),

    "incidents": CSVSchema(
        filename="incidents.csv",
        required_columns=(
            "incident_id",
            "external_id",
            "organization_id",
            "title",
            "severity",
            "status",
            "description",
            "created_at",
            "resolved_at",
        ),
        id_column="incident_id",
        id_prefix="INC",
        required_non_empty=(
            "incident_id",
            "external_id",
            "organization_id",
            "title",
            "created_at",
        ),
    ),

    "investigations": CSVSchema(
        filename="investigations.csv",
        required_columns=(
            "investigation_id",
            "alert_id",
            "analyst_id",
            "started_at",
            "completed_at",
            "duration_minutes",
            "actions_performed",
            "queries_executed",
            "evidence_reviewed",
            "investigation_notes",
            "findings",
            "escalation_decision",
        ),
        id_column="investigation_id",
        id_prefix="INV",
        required_non_empty=(
            "investigation_id",
            "alert_id",
            "analyst_id",
            "started_at",
        ),
    ),

    "asset_activity": CSVSchema(
        filename="asset_activity.csv",
        required_columns=(
            "activity_id",
            "asset_id",
            "timestamp",
            "event_count",
            "log_sources_active",
            "network_events",
            "authentication_events",
            "status",
        ),
        id_column="activity_id",
        id_prefix="ACT",
        required_non_empty=(
            "activity_id",
            "asset_id",
            "timestamp",
        ),
    ),

    "peer_benchmarks": CSVSchema(
        filename="peer_benchmarks.csv",
        required_columns=(
            "benchmark_id",
            "organization_id",
            "metric_name",
            "metric_value",
            "peer_mean",
            "peer_stddev",
            "benchmark_period",
            "calculated_at",
        ),
        id_column="benchmark_id",
        id_prefix="BENCH",
        required_non_empty=(
            "benchmark_id",
            "organization_id",
            "metric_name",
            "benchmark_period",
            "calculated_at",
        ),
    ),
}