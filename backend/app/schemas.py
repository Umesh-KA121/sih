from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


# ============================================================
# Common
# ============================================================

class APIResponse(BaseModel):
    success: bool = True
    message: str | None = None


# ============================================================
# Dashboard
# ============================================================

class DashboardOverview(BaseModel):
    total_organizations: int
    total_analysts: int
    total_assets: int
    total_alerts: int
    total_incidents: int
    total_investigations: int
    open_alerts: int
    critical_alerts: int


class RiskSummary(BaseModel):
    overall_risk_score: float
    severity: str
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


# ============================================================
# Findings
# ============================================================

class FindingResponse(BaseModel):
    finding_id: str
    organization_id: str
    category: str
    severity: str
    title: str
    description: str
    affected_entity: str
    affected_entity_id: str
    risk_score: float
    confidence: float
    evidence: list[str]
    indicators: list[str]
    status: str


class FindingListResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    limit: int
    data: list[FindingResponse]


# ============================================================
# Alerts
# ============================================================

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: Any
    external_id: Any
    organization_id: Any
    asset_id: Any
    analyst_id: Any
    alert_type: Any
    severity: Any
    status: Any
    created_at: Any
    closed_at: Any
    closure_time_minutes: Any
    investigation_notes: Any
    evidence_reviewed: Any
    escalated: Any
    false_positive: Any
    incident_id: Any


# ============================================================
# Analysts
# ============================================================

class AnalystResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analyst_id: Any
    organization_id: Any
    name: Any
    role: Any
    team: Any
    experience_years: Any
    shift: Any
    status: Any
    joined_at: Any


class AnalystMetricResponse(BaseModel):
    analyst_id: str
    name: str
    total_alerts: int
    closed_alerts: int
    open_alerts: int
    investigating_alerts: int
    escalated_alerts: int
    false_positives: int
    evidence_review_rate: float
    escalation_rate: float
    avg_closure_time: float | None
    total_investigations: int
    avg_investigation_time: float | None
    risk_score: float
    risk_level: str
    indicators: list[str]


# ============================================================
# Assets
# ============================================================

class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: Any
    organization_id: Any
    asset_identifier: Any
    asset_name: Any
    asset_type: Any
    criticality: Any
    environment: Any
    location: Any
    status: Any


# ============================================================
# Investigations
# ============================================================

class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    investigation_id: Any
    alert_id: Any
    analyst_id: Any
    started_at: Any
    completed_at: Any
    duration_minutes: Any
    actions_performed: Any
    queries_executed: Any
    evidence_reviewed: Any
    investigation_notes: Any
    findings: Any
    escalation_decision: Any