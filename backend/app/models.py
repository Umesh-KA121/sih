from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    ForeignKey,
    Index,
)

from app.database import Base


# ============================================================
# ORGANIZATION
# ============================================================

class Organization(Base):
    __tablename__ = "organizations"

    organization_id = Column(
        String(20),
        primary_key=True,
    )

    organization_name = Column(
        String(150),
        nullable=False,
    )

    industry = Column(
        String(100),
        nullable=True,
    )

    organization_size = Column(
        String(50),
        nullable=True,
    )

    soc_maturity = Column(
        String(50),
        nullable=True,
    )

    region = Column(
        String(100),
        nullable=True,
    )

    created_at = Column(
        Date,
        nullable=True,
    )


# ============================================================
# ANALYST
# ============================================================

class Analyst(Base):
    __tablename__ = "analysts"

    analyst_id = Column(
        String(20),
        primary_key=True,
    )

    organization_id = Column(
        String(20),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )

    name = Column(
        String(150),
        nullable=False,
    )

    role = Column(
        String(100),
        nullable=True,
    )

    team = Column(
        String(100),
        nullable=True,
    )

    experience_years = Column(
        Integer,
        nullable=True,
    )

    shift = Column(
        String(50),
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=True,
    )

    joined_at = Column(
        Date,
        nullable=True,
    )


# ============================================================
# ASSET
# ============================================================

class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(
        String(20),
        primary_key=True,
    )

    organization_id = Column(
        String(20),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )

    asset_identifier = Column(
        String(100),
        nullable=False,
    )

    asset_name = Column(
        String(150),
        nullable=False,
    )

    asset_type = Column(
        String(100),
        nullable=True,
    )

    criticality = Column(
        String(50),
        nullable=True,
    )

    environment = Column(
        String(50),
        nullable=True,
    )

    location = Column(
        String(150),
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=True,
    )


# ============================================================
# ALERT
# ============================================================

class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(
        String(20),
        primary_key=True,
    )

    external_id = Column(
        String(100),
        nullable=False,
    )

    organization_id = Column(
        String(20),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )

    asset_id = Column(
        String(20),
        ForeignKey("assets.asset_id"),
        nullable=False,
        index=True,
    )

    analyst_id = Column(
        String(20),
        ForeignKey("analysts.analyst_id"),
        nullable=True,
        index=True,
    )

    alert_type = Column(
        String(100),
        nullable=True,
    )

    severity = Column(
        String(50),
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=True,
    )

    closed_at = Column(
        DateTime,
        nullable=True,
    )

    closure_time_minutes = Column(
        Float,
        nullable=True,
    )

    investigation_notes = Column(
        Text,
        nullable=True,
    )

    evidence_reviewed = Column(
        Boolean,
        nullable=True,
    )

    escalated = Column(
        Boolean,
        nullable=True,
    )

    false_positive = Column(
        Boolean,
        nullable=True,
    )

    incident_id = Column(
        String(20),
        nullable=True,
        index=True,
    )


# ============================================================
# INCIDENT
# ============================================================

class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(
        String(20),
        primary_key=True,
    )

    external_id = Column(
        String(100),
        nullable=False,
    )

    organization_id = Column(
        String(20),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )

    title = Column(
        String(200),
        nullable=False,
    )

    severity = Column(
        String(50),
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=True,
    )

    description = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=True,
    )

    resolved_at = Column(
        DateTime,
        nullable=True,
    )


# ============================================================
# INVESTIGATION
# ============================================================

class Investigation(Base):
    __tablename__ = "investigations"

    investigation_id = Column(
        String(20),
        primary_key=True,
    )

    alert_id = Column(
        String(20),
        ForeignKey("alerts.alert_id"),
        nullable=False,
        index=True,
    )

    analyst_id = Column(
        String(20),
        ForeignKey("analysts.analyst_id"),
        nullable=False,
        index=True,
    )

    started_at = Column(
        DateTime,
        nullable=True,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )

    duration_minutes = Column(
        Integer,
        nullable=True,
    )

    actions_performed = Column(
        Text,
        nullable=True,
    )

    queries_executed = Column(
        Integer,
        nullable=True,
    )

    evidence_reviewed = Column(
        Boolean,
        nullable=True,
    )

    investigation_notes = Column(
        Text,
        nullable=True,
    )

    findings = Column(
        Text,
        nullable=True,
    )

    escalation_decision = Column(
        Boolean,
        nullable=True,
    )


# ============================================================
# ASSET ACTIVITY
# ============================================================

class AssetActivity(Base):
    __tablename__ = "asset_activity"

    activity_id = Column(
        String(20),
        primary_key=True,
    )

    asset_id = Column(
        String(20),
        ForeignKey("assets.asset_id"),
        nullable=False,
        index=True,
    )

    timestamp = Column(
        DateTime,
        nullable=True,
    )

    event_count = Column(
        Integer,
        nullable=True,
    )

    log_sources_active = Column(
        Integer,
        nullable=True,
    )

    network_events = Column(
        Integer,
        nullable=True,
    )

    authentication_events = Column(
        Integer,
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=True,
    )


# ============================================================
# PEER BENCHMARK
# ============================================================

class PeerBenchmark(Base):
    __tablename__ = "peer_benchmarks"

    benchmark_id = Column(
        String(20),
        primary_key=True,
    )

    organization_id = Column(
        String(20),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )

    metric_name = Column(
        String(100),
        nullable=False,
    )

    metric_value = Column(
        Float,
        nullable=True,
    )

    peer_mean = Column(
        Float,
        nullable=True,
    )

    peer_stddev = Column(
        Float,
        nullable=True,
    )

    benchmark_period = Column(
        String(50),
        nullable=True,
    )

    calculated_at = Column(
        DateTime,
        nullable=True,
    )