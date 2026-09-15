from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ============================================================
# ORGANIZATION
# ============================================================

class Organization(Base):
    __tablename__ = "organizations"

    organization_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    sector: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    size: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    location: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    analysts: Mapped[list["Analyst"]] = relationship(
        back_populates="organization",
    )

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="organization",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="organization",
    )


# ============================================================
# ANALYST
# ============================================================

class Analyst(Base):
    __tablename__ = "analysts"

    analyst_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    role: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    team: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    experience_years: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    shift: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    status: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="analysts",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="analyst",
    )

    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="analyst",
    )


# ============================================================
# ASSET
# ============================================================

class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    name: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    asset_type: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    criticality: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    environment: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    status: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="assets",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="asset",
    )

    activities: Mapped[list["AssetActivity"]] = relationship(
        back_populates="asset",
    )


# ============================================================
# ALERT
# ============================================================

class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    external_id: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.asset_id"),
        nullable=True,
    )

    analyst_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysts.analyst_id"),
        nullable=True,
    )

    alert_type: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    status: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    closure_time_minutes: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    investigation_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence_reviewed: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    escalated: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    false_positive: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    incident_id: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="alerts",
    )

    analyst: Mapped["Analyst | None"] = relationship(
        back_populates="alerts",
    )

    asset: Mapped["Asset | None"] = relationship(
        back_populates="alerts",
    )

    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="alert",
    )


# ============================================================
# INCIDENT
# ============================================================

class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    incident_type: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    status: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


# ============================================================
# INVESTIGATION
# ============================================================

class Investigation(Base):
    __tablename__ = "investigations"

    investigation_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.alert_id"),
        nullable=False,
    )

    analyst_id: Mapped[str] = mapped_column(
        ForeignKey("analysts.analyst_id"),
        nullable=False,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    duration_minutes: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    actions_performed: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    queries_executed: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence_reviewed: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    investigation_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    findings: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    escalation_decision: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    alert: Mapped["Alert"] = relationship(
        back_populates="investigations",
    )

    analyst: Mapped["Analyst"] = relationship(
        back_populates="investigations",
    )


# ============================================================
# ASSET ACTIVITY
# ============================================================

class AssetActivity(Base):
    __tablename__ = "asset_activity"

    activity_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id"),
        nullable=False,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    activity_type: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    timestamp: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    source: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    asset: Mapped["Asset"] = relationship(
        back_populates="activities",
    )


# ============================================================
# PEER BENCHMARK
# ============================================================

class PeerBenchmark(Base):
    __tablename__ = "peer_benchmarks"

    benchmark_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )

    metric_name: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    peer_group: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    peer_mean: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    peer_median: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    peer_stddev: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    sample_size: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )