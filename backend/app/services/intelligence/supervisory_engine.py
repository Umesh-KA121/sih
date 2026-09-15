"""
SAT-SA Supervisory Intelligence Engine
=======================================

Purpose
-------
Combines analyst, alert and investigation data into a supervisory
risk assessment.

Pipeline
--------
A. Analytics
B. Rule Intelligence
C. Investigation DNA
D. Negative Space Detection
E. Gaming Detection
F. Peer Benchmarking
G. Behavioral Analytics
H. Lightweight NLP
I. Unified Risk Engine

Risk weights
------------
Rule Score          -> 40%
Behavior Score      -> 30%
Negative Space      -> 20%
Peer Score          -> 10%

The module intentionally uses lightweight Python logic and SQLAlchemy.
No NumPy / Pandas / Scikit-learn dependency is required.

CLI
---
python -m app.services.intelligence.supervisory_engine
"""

from __future__ import annotations

import math
import re
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.analyst import Analyst
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.asset import Asset
from app.models.asset_activity import AssetActivity


# ============================================================
# Constants
# ============================================================

RULE_WEIGHT = 0.40
BEHAVIOR_WEIGHT = 0.30
NEGATIVE_SPACE_WEIGHT = 0.20
PEER_WEIGHT = 0.10

ENGINE_VERSION = "2.1"

DEFAULT_CACHE_TTL = 60


# ============================================================
# Dataclasses
# ============================================================


@dataclass
class AnalystFinding:
    analyst_id: str
    analyst_name: str

    rule_score: float = 0.0
    behavior_score: float = 0.0
    negative_space_score: float = 0.0
    peer_score: float = 0.0

    score: float = 0.0
    risk_level: str = "LOW"

    indicators: list[str] = field(default_factory=list)

    metrics: dict[str, Any] = field(default_factory=dict)

    rule_findings: list[dict[str, Any]] = field(default_factory=list)
    investigation_dna: dict[str, Any] = field(default_factory=dict)
    gaming_detection: dict[str, Any] = field(default_factory=dict)
    negative_space: list[dict[str, Any]] = field(default_factory=list)
    peer_benchmark: dict[str, Any] = field(default_factory=dict)
    behavioral: dict[str, Any] = field(default_factory=dict)
    nlp: dict[str, Any] = field(default_factory=dict)


# ============================================================
# Generic helpers
# ============================================================


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""

    if value is None:
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Clamp a number into a range."""

    return max(low, min(high, value))

def jaccard_similarity(
    first: Iterable[Any],
    second: Iterable[Any],
) -> float:
    """
    Calculate Jaccard similarity between two collections.

    J(A, B) = |A ∩ B| / |A ∪ B|

    Returns:
        0.0 when both collections are empty.
        A value between 0.0 and 1.0 otherwise.
    """

    first_set = set(first)
    second_set = set(second)

    union = first_set | second_set

    if not union:
        return 0.0

    intersection = first_set & second_set

    return len(intersection) / len(union)

def round_score(value: float) -> float:
    return round(clamp(value), 2)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""

    return re.sub(r"\s+", " ", str(value)).strip()


def tokenize(text: str) -> list[str]:
    return re.findall(r"\b[a-zA-Z0-9_]+\b", text.lower())


def percentile(values: list[float], p: float) -> float:
    """Pure-Python percentile."""

    if not values:
        return 0.0

    if len(values) == 1:
        return values[0]

    ordered = sorted(values)

    position = (len(ordered) - 1) * p
    lower = int(math.floor(position))
    upper = int(math.ceil(position))

    if lower == upper:
        return ordered[lower]

    weight = position - lower

    return (
        ordered[lower] * (1.0 - weight)
        + ordered[upper] * weight
    )


def z_score(
    value: float,
    mean: float,
    stddev: float,
) -> float:
    """
    Fast z-score.

    IMPORTANT:
    Mean/stddev are supplied rather than recalculated for every analyst.
    This avoids the previous O(N²)-style performance problem.
    """

    if stddev <= 0:
        return 0.0

    return (value - mean) / stddev


# ============================================================
# Risk Level
# ============================================================


def risk_level(score: float) -> str:
    score = safe_float(score)

    if score < 25:
        return "LOW"

    if score <= 50:
        return "MEDIUM"

    if score < 90:
        return "HIGH"

    return "CRITICAL"

# ============================================================
# Unified Risk Engine
# ============================================================


def unified_risk(
    rule_score: float,
    behavior_score: float,
    negative_space_score: float,
    peer_score: float,
) -> dict[str, Any]:
    """
    Unified supervisory risk score.

    Rule          = 40%
    Behavior      = 30%
    Negative Space = 20%
    Peer          = 10%
    """

    rule_score = clamp(safe_float(rule_score))
    behavior_score = clamp(safe_float(behavior_score))
    negative_space_score = clamp(
        safe_float(negative_space_score)
    )
    peer_score = clamp(safe_float(peer_score))

    score = (
        rule_score * 0.40
        + behavior_score * 0.30
        + negative_space_score * 0.20
        + peer_score * 0.10
    )

    score = round(score, 2)

    return {
        "score": score,
        "risk_score": score,
        "risk_level": risk_level(score),
        "weights": {
            "rule": 0.40,
            "behavior": 0.30,
            "negative_space": 0.20,
            "peer": 0.10,
        },
        "components": {
            "rule_score": rule_score,
            "behavior_score": behavior_score,
            "negative_space_score": negative_space_score,
            "peer_score": peer_score,
        },
    }


# ============================================================
# Statistics
# ============================================================


@dataclass
class MetricStats:
    mean: float
    stddev: float
    median: float
    p90: float
    p95: float
    minimum: float
    maximum: float


def build_metric_stats(values: Iterable[float]) -> MetricStats:
    values = [safe_float(v) for v in values]

    if not values:
        return MetricStats(
            mean=0.0,
            stddev=0.0,
            median=0.0,
            p90=0.0,
            p95=0.0,
            minimum=0.0,
            maximum=0.0,
        )

    return MetricStats(
        mean=statistics.fmean(values),
        stddev=statistics.pstdev(values) if len(values) > 1 else 0.0,
        median=statistics.median(values),
        p90=percentile(values, 0.90),
        p95=percentile(values, 0.95),
        minimum=min(values),
        maximum=max(values),
    )


# ============================================================
# Data Loading
# ============================================================


def load_data(
    db: Session,
) -> tuple[
    list[Analyst],
    list[Alert],
    list[Investigation],
    list[Asset],
    list[AssetActivity],
]:
    """
    Load all datasets required by the supervisory engine.
    """

    analysts = db.query(Analyst).all()
    alerts = db.query(Alert).all()
    investigations = db.query(
        Investigation
    ).all()
    assets = db.query(Asset).all()
    activities = db.query(
        AssetActivity
    ).all()

    return (
        analysts,
        alerts,
        investigations,
        assets,
        activities,
    )

# ============================================================
# Index Building
# ============================================================


def build_indexes(
    analysts: list[Analyst],
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    alerts_by_analyst: dict[Any, list[Alert]] = defaultdict(list)
    investigations_by_analyst: dict[Any, list[Investigation]] = (
        defaultdict(list)
    )
    investigations_by_alert: dict[Any, list[Investigation]] = (
        defaultdict(list)
    )

    alerts_by_asset: dict[Any, list[Alert]] = defaultdict(list)

    for alert in alerts:

        if alert.analyst_id is not None:
            alerts_by_analyst[alert.analyst_id].append(alert)

        if alert.asset_id is not None:
            alerts_by_asset[alert.asset_id].append(alert)

    for investigation in investigations:

        if investigation.analyst_id is not None:
            investigations_by_analyst[
                investigation.analyst_id
            ].append(investigation)

        if investigation.alert_id is not None:
            investigations_by_alert[
                investigation.alert_id
            ].append(investigation)

    return {
        "alerts_by_analyst": alerts_by_analyst,
        "investigations_by_analyst": investigations_by_analyst,
        "investigations_by_alert": investigations_by_alert,
        "alerts_by_asset": alerts_by_asset,
    }


# ============================================================
# Analyst Metrics
# ============================================================


def analyst_metrics(
    analyst: Analyst,
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    alert_count = len(alerts)
    investigation_count = len(investigations)

    closure_times = [
        safe_float(alert.closure_time_minutes)
        for alert in alerts
        if alert.closure_time_minutes is not None
    ]

    investigation_durations = [
        safe_float(inv.duration_minutes)
        for inv in investigations
        if inv.duration_minutes is not None
    ]

    evidence_values = [
        1.0 if bool(alert.evidence_reviewed) else 0.0
        for alert in alerts
    ]

    escalation_values = [
        1.0 if bool(alert.escalated) else 0.0
        for alert in alerts
    ]

    critical_alerts = [
        alert
        for alert in alerts
        if str(getattr(alert, "severity", "")).lower()
        == "critical"
    ]

    critical_escalations = [
        alert
        for alert in critical_alerts
        if bool(alert.escalated)
    ]

    avg_closure = (
        statistics.fmean(closure_times)
        if closure_times
        else 0.0
    )

    avg_investigation = (
        statistics.fmean(investigation_durations)
        if investigation_durations
        else 0.0
    )

    evidence_rate = (
        statistics.fmean(evidence_values) * 100
        if evidence_values
        else 0.0
    )

    escalation_rate = (
        statistics.fmean(escalation_values) * 100
        if escalation_values
        else 0.0
    )

    critical_escalation_rate = (
        len(critical_escalations)
        / len(critical_alerts)
        * 100
        if critical_alerts
        else 0.0
    )

    return {
        "alert_count": alert_count,
        "investigation_count": investigation_count,
        "average_closure_time": round(avg_closure, 2),
        "average_investigation_duration": round(
            avg_investigation,
            2,
        ),
        "evidence_review_rate": round(evidence_rate, 2),
        "escalation_rate": round(escalation_rate, 2),
        "critical_alert_count": len(critical_alerts),
        "critical_escalation_rate": round(
            critical_escalation_rate,
            2,
        ),
    }


# ============================================================
# Rule Intelligence
# ============================================================


def rule_intelligence(
    metrics: dict[str, Any],
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    findings: list[dict[str, Any]] = []
    score = 0.0

    avg_closure = safe_float(
        metrics["average_closure_time"]
    )

    evidence_rate = safe_float(
        metrics["evidence_review_rate"]
    )

    escalation_rate = safe_float(
        metrics["escalation_rate"]
    )

    investigation_count = int(
        metrics["investigation_count"]
    )

    avg_investigation = safe_float(
        metrics["average_investigation_duration"]
    )

    critical_count = int(
        metrics["critical_alert_count"]
    )

    critical_escalation_rate = safe_float(
        metrics["critical_escalation_rate"]
    )

    # --------------------------------------------------------
    # FAST_CLOSURE
    # --------------------------------------------------------

    if avg_closure > 0 and avg_closure <= 10:
        findings.append(
            {
                "rule": "FAST_CLOSURE",
                "severity": "HIGH",
                "message": (
                    "Suspiciously fast alert closure."
                ),
                "score": 20,
            }
        )

        score += 20

    # --------------------------------------------------------
    # SHORT_NOTES
    # --------------------------------------------------------

    note_lengths = []

    for alert in alerts:
        note = normalize_text(
            getattr(alert, "investigation_notes", "")
        )

        if note:
            note_lengths.append(len(tokenize(note)))

    avg_note_length = (
        statistics.fmean(note_lengths)
        if note_lengths
        else 0.0
    )

    if note_lengths and avg_note_length < 8:
        findings.append(
            {
                "rule": "SHORT_NOTES",
                "severity": "MEDIUM",
                "message": (
                    "Investigation notes are unusually short."
                ),
                "score": 15,
            }
        )

        score += 15

    # --------------------------------------------------------
    # NO_EVIDENCE
    # --------------------------------------------------------

    if alerts and evidence_rate < 50:
        findings.append(
            {
                "rule": "NO_EVIDENCE",
                "severity": "HIGH",
                "message": (
                    "Low evidence-review rate."
                ),
                "score": 20,
            }
        )

        score += 20

    # --------------------------------------------------------
    # NO_ESCALATION
    # --------------------------------------------------------

    if critical_count > 0 and critical_escalation_rate < 50:
        findings.append(
            {
                "rule": "NO_ESCALATION",
                "severity": "HIGH",
                "message": (
                    "Critical alerts show low escalation "
                    "activity."
                ),
                "score": 20,
            }
        )

        score += 20

    elif alerts and escalation_rate < 20:
        findings.append(
            {
                "rule": "NO_ESCALATION",
                "severity": "MEDIUM",
                "message": (
                    "Overall escalation rate is low."
                ),
                "score": 10,
            }
        )

        score += 10

    # --------------------------------------------------------
    # SHALLOW_INVESTIGATION
    # --------------------------------------------------------

    if alerts and investigation_count < max(
        1,
        int(len(alerts) * 0.5),
    ):
        findings.append(
            {
                "rule": "SHALLOW_INVESTIGATION",
                "severity": "HIGH",
                "message": (
                    "Investigation activity is shallow "
                    "relative to alert workload."
                ),
                "score": 15,
            }
        )

        score += 15

    # --------------------------------------------------------
    # VERY_SHORT_INVESTIGATIONS
    # --------------------------------------------------------

    if (
        investigation_count > 0
        and avg_investigation <= 10
    ):
        findings.append(
            {
                "rule": "VERY_SHORT_INVESTIGATIONS",
                "severity": "HIGH",
                "message": (
                    "Investigations are completed unusually "
                    "quickly."
                ),
                "score": 15,
            }
        )

        score += 15

    # --------------------------------------------------------
    # REPEATED_NOTES
    # --------------------------------------------------------

    notes = [
        normalize_text(
            getattr(inv, "investigation_notes", "")
        ).lower()
        for inv in investigations
    ]

    notes = [note for note in notes if note]

    duplicate_count = 0

    if notes:
        counts = Counter(notes)

        duplicate_count = sum(
            count - 1
            for count in counts.values()
            if count > 1
        )

    if duplicate_count > 0:
        findings.append(
            {
                "rule": "REPEATED_NOTES",
                "severity": "MEDIUM",
                "message": (
                    "Repeated investigation narratives detected."
                ),
                "score": 15,
            }
        )

        score += 15

    return {
        "score": round_score(score),
        "findings": findings,
        "average_note_length_words": round(
            avg_note_length,
            2,
        ),
        "repeated_notes": duplicate_count,
    }


# ============================================================
# Investigation DNA
# ============================================================


def investigation_dna(
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    if not investigations:
        return {
            "score": 0.0,
            "evidence_discipline": 0.0,
            "investigation_depth": 0.0,
            "query_activity": 0.0,
            "action_activity": 0.0,
            "note_quality": 0.0,
            "closure_behaviour": 0.0,
        }

    # --------------------------------------------------------
    # Evidence Discipline
    # --------------------------------------------------------

    evidence_reviewed = sum(
        1
        for alert in alerts
        if bool(alert.evidence_reviewed)
    )

    evidence_discipline = (
        evidence_reviewed / len(alerts) * 100
        if alerts
        else 0
    )

    # --------------------------------------------------------
    # Investigation Depth
    # --------------------------------------------------------

    durations = [
        safe_float(inv.duration_minutes)
        for inv in investigations
        if inv.duration_minutes is not None
    ]

    avg_duration = (
        statistics.fmean(durations)
        if durations
        else 0
    )

    investigation_depth = clamp(
        avg_duration * 2
    )

    # --------------------------------------------------------
    # Query Activity
    # --------------------------------------------------------

    query_counts = []

    for inv in investigations:
        value = getattr(
            inv,
            "queries_executed",
            0,
        )

        try:
            query_counts.append(float(value or 0))
        except (TypeError, ValueError):
            query_counts.append(0.0)

    avg_queries = (
        statistics.fmean(query_counts)
        if query_counts
        else 0
    )

    query_activity = clamp(
        avg_queries * 10
    )

    # --------------------------------------------------------
    # Action Activity
    # --------------------------------------------------------

    action_counts = []

    for inv in investigations:
        value = getattr(
            inv,
            "actions_performed",
            "",
        )

        if isinstance(value, (list, tuple)):
            action_counts.append(len(value))
        else:
            text = normalize_text(value)

            if not text:
                action_counts.append(0)
            else:
                action_counts.append(
                    len(
                        [
                            x
                            for x in re.split(
                                r"[,;|]",
                                text,
                            )
                            if x.strip()
                        ]
                    )
                )

    avg_actions = (
        statistics.fmean(action_counts)
        if action_counts
        else 0
    )

    action_activity = clamp(
        avg_actions * 10
    )

    # --------------------------------------------------------
    # Note Quality
    # --------------------------------------------------------

    note_lengths = []

    for inv in investigations:
        text = normalize_text(
            getattr(
                inv,
                "investigation_notes",
                "",
            )
        )

        note_lengths.append(
            len(tokenize(text))
        )

    avg_note_words = (
        statistics.fmean(note_lengths)
        if note_lengths
        else 0
    )

    note_quality = clamp(
        avg_note_words * 5
    )

    # --------------------------------------------------------
    # Closure Behaviour
    # --------------------------------------------------------

    closure_times = [
        safe_float(alert.closure_time_minutes)
        for alert in alerts
        if alert.closure_time_minutes is not None
    ]

    avg_closure = (
        statistics.fmean(closure_times)
        if closure_times
        else 0
    )

    if avg_closure <= 10:
        closure_behaviour = 20
    elif avg_closure <= 30:
        closure_behaviour = 60
    else:
        closure_behaviour = 100

    # --------------------------------------------------------
    # Overall DNA score
    # --------------------------------------------------------

    score = statistics.fmean(
        [
            evidence_discipline,
            investigation_depth,
            query_activity,
            action_activity,
            note_quality,
            closure_behaviour,
        ]
    )

    return {
        "score": round_score(score),
        "evidence_discipline": round_score(
            evidence_discipline
        ),
        "investigation_depth": round_score(
            investigation_depth
        ),
        "query_activity": round_score(
            query_activity
        ),
        "action_activity": round_score(
            action_activity
        ),
        "note_quality": round_score(
            note_quality
        ),
        "closure_behaviour": round_score(
            closure_behaviour
        ),
    }


# ============================================================
# Lightweight NLP
# ============================================================


def lightweight_nlp(
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    texts: list[str] = []

    for alert in alerts:
        text = normalize_text(
            getattr(
                alert,
                "investigation_notes",
                "",
            )
        )

        if text:
            texts.append(text)

    for investigation in investigations:
        text = normalize_text(
            getattr(
                investigation,
                "investigation_notes",
                "",
            )
        )

        if text:
            texts.append(text)

    if not texts:
        return {
            "score": 0.0,
            "note_count": 0,
            "average_words": 0.0,
            "evidence_reference_rate": 0.0,
            "finding_conclusion_rate": 0.0,
            "repetition_rate": 0.0,
            "narrative_quality": 0.0,
        }

    word_counts = [
        len(tokenize(text))
        for text in texts
    ]

    average_words = statistics.fmean(
        word_counts
    )

    evidence_pattern = re.compile(
        r"\b("
        r"evidence|log|logs|ioc|indicator|"
        r"artifact|packet|event|trace|"
        r"hash|ip|address|timestamp"
        r")\b",
        re.IGNORECASE,
    )

    finding_pattern = re.compile(
        r"\b("
        r"finding|findings|conclusion|"
        r"concluded|determined|result|"
        r"root cause|assessment"
        r")\b",
        re.IGNORECASE,
    )

    evidence_count = sum(
        1
        for text in texts
        if evidence_pattern.search(text)
    )

    finding_count = sum(
        1
        for text in texts
        if finding_pattern.search(text)
    )

    unique_texts = len(set(
        text.lower()
        for text in texts
    ))

    repetition_rate = (
        1
        - unique_texts / len(texts)
    ) * 100

    evidence_reference_rate = (
        evidence_count / len(texts)
    ) * 100

    finding_conclusion_rate = (
        finding_count / len(texts)
    ) * 100

    narrative_quality = clamp(
        (
            min(average_words, 40) / 40 * 40
            + evidence_reference_rate * 0.30
            + finding_conclusion_rate * 0.20
            - repetition_rate * 0.20
        )
    )

    return {
        "score": round_score(narrative_quality),
        "note_count": len(texts),
        "average_words": round(
            average_words,
            2,
        ),
        "evidence_reference_rate": round(
            evidence_reference_rate,
            2,
        ),
        "finding_conclusion_rate": round(
            finding_conclusion_rate,
            2,
        ),
        "repetition_rate": round(
            repetition_rate,
            2,
        ),
        "narrative_quality": round_score(
            narrative_quality
        ),
    }


# ============================================================
# Gaming Detection
# ============================================================


def gaming_detection(
    alerts: list[Alert],
    investigations: list[Investigation],
) -> dict[str, Any]:

    indicators: list[str] = []
    score = 0.0

    # --------------------------------------------------------
    # Repeated notes
    # --------------------------------------------------------

    notes = [
        normalize_text(
            getattr(
                inv,
                "investigation_notes",
                "",
            )
        ).lower()
        for inv in investigations
    ]

    notes = [x for x in notes if x]

    if notes:
        unique_notes = len(set(notes))

        repetition_rate = (
            1
            - unique_notes / len(notes)
        ) * 100
    else:
        repetition_rate = 0.0

    if repetition_rate >= 50:
        indicators.append(
            "Repeated investigation notes"
        )
        score += 30

    # --------------------------------------------------------
    # Repeated closure durations
    # --------------------------------------------------------

    closure_times = [
        safe_float(alert.closure_time_minutes)
        for alert in alerts
        if alert.closure_time_minutes is not None
    ]

    if closure_times:
        counts = Counter(
            round(x, 2)
            for x in closure_times
        )

        most_common_count = (
            counts.most_common(1)[0][1]
        )

        repeated_duration_rate = (
            most_common_count
            / len(closure_times)
            * 100
        )
    else:
        repeated_duration_rate = 0.0

    if repeated_duration_rate >= 50:
        indicators.append(
            "Suspiciously uniform closure durations"
        )
        score += 25

    # --------------------------------------------------------
    # Uniform workflow
    # --------------------------------------------------------

    statuses = [
        normalize_text(
            getattr(
                alert,
                "status",
                "",
            )
        ).lower()
        for alert in alerts
    ]

    if len(statuses) >= 3:
        status_counts = Counter(statuses)

        dominant_status_rate = (
            status_counts.most_common(1)[0][1]
            / len(statuses)
            * 100
        )
    else:
        dominant_status_rate = 0.0

    if dominant_status_rate >= 90:
        indicators.append(
            "Suspiciously uniform workflow"
        )
        score += 20

    # --------------------------------------------------------
    # High closure + shallow investigation
    # --------------------------------------------------------

    if alerts and investigations:

        closure_times = [
            safe_float(alert.closure_time_minutes)
            for alert in alerts
            if alert.closure_time_minutes is not None
        ]

        avg_closure = (
            statistics.fmean(closure_times)
            if closure_times
            else 0
        )

        investigation_ratio = (
            len(investigations)
            / len(alerts)
        )

        if avg_closure <= 15 and investigation_ratio < 0.5:
            indicators.append(
                "High closure speed with shallow investigation"
            )
            score += 30

    return {
        "score": round_score(score),
        "indicators": indicators,
        "repetition_rate": round(
            repetition_rate,
            2,
        ),
        "repeated_closure_rate": round(
            repeated_duration_rate,
            2,
        ),
        "dominant_workflow_rate": round(
            dominant_status_rate,
            2,
        ),
    }


# ============================================================
# Negative Space Detection
# ============================================================


def negative_space_analysis(
    analyst: Any,
    alerts: list[Any],
    investigations: list[Any],
    assets: list[Any] | None = None,
    activities: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Detect expected-but-missing security activity.

    Negative-space categories:
        1. Critical asset silence
        2. Expected alert missing
        3. Expected investigation missing
        4. Expected escalation missing

    The function intentionally produces findings rather than silently
    converting missing behaviour into a normal/zero score.
    """

    findings: list[dict[str, Any]] = []

    analyst_id = getattr(analyst, "analyst_id", None)

    analyst_alerts = [
        alert
        for alert in alerts
        if getattr(alert, "analyst_id", None) == analyst_id
    ]

    analyst_investigations = [
        investigation
        for investigation in investigations
        if getattr(investigation, "analyst_id", None) == analyst_id
    ]


    # ------------------------------------------------------------
    # 1. CRITICAL ASSET SILENCE
    # ------------------------------------------------------------

    if assets:
        activity_by_asset: dict[Any, list[Any]] = defaultdict(list)

        for activity in activities or []:
            asset_id = getattr(activity, "asset_id", None)

            if asset_id is not None:
                activity_by_asset[asset_id].append(activity)

        critical_assets = [
            asset
            for asset in assets
            if str(getattr(asset, "criticality", "")).upper()
            in {"CRITICAL", "HIGH"}
        ]

        for asset in critical_assets:
            asset_id = getattr(asset, "asset_id", None)

            asset_activity = activity_by_asset.get(asset_id, [])

            # No activity record at all = strongest silence signal.
            if not asset_activity:
                findings.append(
                    {
                        "category": "CRITICAL_ASSET_SILENCE",
                        "entity_type": "asset",
                        "entity_id": asset_id,
                        "analyst_id": analyst_id,
                        "score": (
                            90.0
                            if str(
                                getattr(asset, "criticality", "")
                            ).upper()
                            == "CRITICAL"
                            else 80.0
                        ),
                        "severity": (
                            "CRITICAL"
                            if str(
                                getattr(asset, "criticality", "")
                            ).upper()
                            == "CRITICAL"
                            else "HIGH"
                        ),
                        "reason": (
                            "Critical/high-criticality asset has no "
                            "recorded activity."
                        ),
                    }
                )

                continue

            # Sort by timestamp where possible.
            asset_activity = sorted(
                asset_activity,
                key=lambda x: getattr(x, "timestamp", None)
                or datetime.min,
            )

            latest = asset_activity[-1]

            event_count = safe_float(
                getattr(latest, "event_count", 0)
            )

            log_sources = safe_float(
                getattr(latest, "log_sources_active", 0)
            )

            network_events = safe_float(
                getattr(latest, "network_events", 0)
            )

            authentication_events = safe_float(
                getattr(latest, "authentication_events", 0)
            )

            total_activity = (
                event_count
                + log_sources
                + network_events
                + authentication_events
            )

            if total_activity <= 0:
                findings.append(
                    {
                        "category": "CRITICAL_ASSET_SILENCE",
                        "entity_type": "asset",
                        "entity_id": asset_id,
                        "analyst_id": analyst_id,
                        "score": 85.0,
                        "severity": "HIGH",
                        "reason": (
                            "Critical/high-criticality asset has a "
                            "latest activity record with no observed "
                            "security activity."
                        ),
                    }
                )
    # ------------------------------------------------------------
    # 2. EXPECTED ALERT / INVESTIGATION / ESCALATION
    # ------------------------------------------------------------

    # Group investigations by alert.
    investigations_by_alert: dict[Any, list[Any]] = defaultdict(list)

    for investigation in investigations:
        alert_id = getattr(investigation, "alert_id", None)

        if alert_id is not None:
            investigations_by_alert[alert_id].append(investigation)

    for alert in analyst_alerts:
        alert_id = getattr(alert, "alert_id", None)

        severity = str(
            getattr(alert, "severity", "")
        ).upper()

        status = str(
            getattr(alert, "status", "")
        ).upper()

        escalated = bool(
            getattr(alert, "escalated", False)
        )

        alert_investigations = investigations_by_alert.get(
            alert_id,
            [],
        )

        # --------------------------------------------------------
        # 2A. EXPECTED INVESTIGATION MISSING
        # --------------------------------------------------------

        high_priority = severity in {
            "CRITICAL",
            "HIGH",
        }

        if high_priority and not alert_investigations:
            findings.append(
                {
                    "category": "EXPECTED_INVESTIGATION_MISSING",
                    "entity_type": "alert",
                    "entity_id": alert_id,
                    "analyst_id": analyst_id,
                    "score": 88.0 if severity == "CRITICAL" else 78.0,
                    "severity": (
                        "CRITICAL"
                        if severity == "CRITICAL"
                        else "HIGH"
                    ),
                    "reason": (
                        f"{severity} severity alert has no "
                        "associated investigation."
                    ),
                }
            )

        # --------------------------------------------------------
        # 2B. EXPECTED ESCALATION MISSING
        # --------------------------------------------------------

        # A critical alert that is closed without escalation is a
        # stronger negative-space signal.
        if severity == "CRITICAL":
            if status in {
                "CLOSED",
                "RESOLVED",
                "COMPLETED",
            } and not escalated:

                findings.append(
                    {
                        "category": "EXPECTED_ESCALATION_MISSING",
                        "entity_type": "alert",
                        "entity_id": alert_id,
                        "analyst_id": analyst_id,
                        "score": 92.0,
                        "severity": "CRITICAL",
                        "reason": (
                            "Critical alert was closed/resolved "
                            "without escalation."
                        ),
                    }
                )

        # --------------------------------------------------------
        # 2C. INVESTIGATION ESCALATION DECISION MISSING
        # --------------------------------------------------------

        if alert_investigations:
            for investigation in alert_investigations:
                decision = str(
                    getattr(
                        investigation,
                        "escalation_decision",
                        "",
                    )
                    or ""
                ).strip().upper()

                if severity in {"CRITICAL", "HIGH"}:
                    if not decision:
                        findings.append(
                            {
                                "category": (
                                    "EXPECTED_ESCALATION_MISSING"
                                ),
                                "entity_type": "investigation",
                                "entity_id": getattr(
                                    investigation,
                                    "investigation_id",
                                    None,
                                ),
                                "analyst_id": analyst_id,
                                "score": (
                                    86.0
                                    if severity == "CRITICAL"
                                    else 72.0
                                ),
                                "severity": (
                                    "CRITICAL"
                                    if severity == "CRITICAL"
                                    else "HIGH"
                                ),
                                "reason": (
                                    f"{severity} investigation "
                                    "contains no escalation decision."
                                ),
                            }
                        )

    # ------------------------------------------------------------
    # 3. EXPECTED ALERT MISSING
    # ------------------------------------------------------------
    #
    # We do not fabricate alerts from arbitrary activity.
    #
    # Instead, use asset activity that explicitly indicates abnormal
    # operational/security activity as an expectation signal.
    #
    # This keeps the detector conservative: it only raises the
    # finding when the available dataset contains enough evidence.
    # ------------------------------------------------------------

    if assets and activities:
        alerts_by_asset: dict[Any, list[Any]] = defaultdict(list)

        for alert in alerts:
            asset_id = getattr(alert, "asset_id", None)

            if asset_id is not None:
                alerts_by_asset[asset_id].append(alert)

        for activity in activities:
            asset_id = getattr(activity, "asset_id", None)

            if asset_id is None:
                continue

            event_count = safe_float(
                getattr(activity, "event_count", 0)
            )

            network_events = safe_float(
                getattr(activity, "network_events", 0)
            )

            authentication_events = safe_float(
                getattr(activity, "authentication_events", 0)
            )

            suspicious_activity = (
                event_count >= 1000
                or network_events >= 500
                or authentication_events >= 500
            )

            if not suspicious_activity:
                continue

            asset_alerts = alerts_by_asset.get(asset_id, [])

            if asset_alerts:
                continue

            asset = next(
                (
                    item
                    for item in assets
                    if getattr(item, "asset_id", None) == asset_id
                ),
                None,
            )

            criticality = str(
                getattr(asset, "criticality", "")
            ).upper() if asset else ""

            if criticality in {"CRITICAL", "HIGH"}:
                findings.append(
                    {
                        "category": "EXPECTED_ALERT_MISSING",
                        "entity_type": "asset",
                        "entity_id": asset_id,
                        "analyst_id": analyst_id,
                        "score": 82.0,
                        "severity": "HIGH",
                        "reason": (
                            "High/critical asset shows unusually "
                            "high activity but has no recorded alert."
                        ),
                    }
                )

    return findings

# ============================================================
# Peer Benchmark
# ============================================================


def peer_benchmark_scores(
    all_metrics: dict[Any, dict[str, Any]],
    analyst_id: Any,
) -> dict[str, Any]:

    metric_names = [
        "alert_count",
        "average_closure_time",
        "evidence_review_rate",
        "escalation_rate",
        "investigation_count",
        "average_investigation_duration",
    ]

    current = all_metrics.get(
        analyst_id,
        {},
    )

    deviations: list[float] = []

    metric_results: dict[str, Any] = {}

    # Precompute statistics once for each metric.
    stats: dict[str, MetricStats] = {}

    for metric in metric_names:

        values = [
            safe_float(
                metrics.get(metric, 0)
            )
            for metrics in all_metrics.values()
        ]

        stats[metric] = build_metric_stats(values)

    for metric in metric_names:

        value = safe_float(
            current.get(metric, 0)
        )

        metric_stat = stats[metric]

        z = z_score(
            value,
            metric_stat.mean,
            metric_stat.stddev,
        )

        # Absolute deviation from peer mean.
        deviation = abs(z)

        deviations.append(deviation)

        metric_results[metric] = {
            "value": round(value, 2),
            "peer_mean": round(
                metric_stat.mean,
                2,
            ),
            "peer_stddev": round(
                metric_stat.stddev,
                2,
            ),
            "z_score": round(z, 3),
            "deviation": round(
                deviation,
                3,
            ),
        }

    average_deviation = (
        statistics.fmean(deviations)
        if deviations
        else 0
    )

    # Approximately:
    # 0 z-score -> 0 risk
    # 2+ z-score -> 100 risk
    score = clamp(
        average_deviation / 2 * 100
    )

    return {
        "score": round_score(score),
        "average_deviation": round(
            average_deviation,
            3,
        ),
        "metrics": metric_results,
    }


# ============================================================
# Behavioral Analytics
# ============================================================


def behavioral_score(
    all_metrics: dict[Any, dict[str, Any]],
    analyst_id: Any,
) -> dict[str, Any]:

    current = all_metrics.get(
        analyst_id,
        {},
    )

    metric_names = [
        "alert_count",
        "average_closure_time",
        "evidence_review_rate",
        "escalation_rate",
    ]

    stats: dict[str, MetricStats] = {}

    # IMPORTANT:
    # Calculate statistics ONCE instead of calling
    # statistics.pstdev() inside every analyst/metric iteration.

    for metric in metric_names:

        values = [
            safe_float(
                metrics.get(metric, 0)
            )
            for metrics in all_metrics.values()
        ]

        stats[metric] = build_metric_stats(values)

    deviations: dict[str, float] = {}

    for metric in metric_names:

        value = safe_float(
            current.get(metric, 0)
        )

        metric_stat = stats[metric]

        deviations[metric] = abs(
            z_score(
                value,
                metric_stat.mean,
                metric_stat.stddev,
            )
        )

    # --------------------------------------------------------
    # Behavioral risk interpretation
    # --------------------------------------------------------

    score_parts = []

    for metric, deviation in deviations.items():

        score_parts.append(
            clamp(
                deviation / 2 * 100
            )
        )

    score = (
        statistics.fmean(score_parts)
        if score_parts
        else 0
    )

    return {
        "score": round_score(score),
        "deviations": {
            metric: round(
                value,
                3,
            )
            for metric, value in deviations.items()
        },
    }


# ============================================================
# Analyst Finding Builder
# ============================================================


# ============================================================
# Analyst Finding Builder
# ============================================================


def build_finding(
    analyst: Analyst,
    alerts: list[Alert],
    investigations: list[Investigation],
    all_metrics: dict[Any, dict[str, Any]],
    assets: list[Any] | None = None,
    activities: list[Any] | None = None,
) -> AnalystFinding:

    metrics = analyst_metrics(
        analyst,
        alerts,
        investigations,
    )

    rules = rule_intelligence(
        metrics,
        alerts,
        investigations,
    )

    dna = investigation_dna(
        alerts,
        investigations,
    )

    nlp = lightweight_nlp(
        alerts,
        investigations,
    )

    gaming = gaming_detection(
        alerts,
        investigations,
    )

    # --------------------------------------------------------
    # Negative Space
    # --------------------------------------------------------

    negative_space = negative_space_analysis(
        analyst,
        alerts,
        investigations,
        assets,
        activities,
    )

    # Convert individual negative-space findings into
    # the aggregate score required by the unified risk engine.
    negative_space_score = max(
        (
            safe_float(item.get("score", 0))
            for item in negative_space
            if isinstance(item, dict)
        ),
        default=0.0,
    )

    # --------------------------------------------------------
    # Peer Benchmark
    # --------------------------------------------------------

    peer = peer_benchmark_scores(
        all_metrics,
        analyst.analyst_id,
    )

    # --------------------------------------------------------
    # Behavioral Analytics
    # --------------------------------------------------------

    behavior = behavioral_score(
        all_metrics,
        analyst.analyst_id,
    )

    # --------------------------------------------------------
    # Rule Score
    # --------------------------------------------------------

    rule_score = clamp(
        safe_float(rules.get("score", 0))
        + safe_float(gaming.get("score", 0)) * 0.5
    )

    # --------------------------------------------------------
    # Behavior Score
    # --------------------------------------------------------

    behavior_score_value = clamp(
        (
            safe_float(behavior.get("score", 0))
            * 0.70
        )
        + (
            safe_float(dna.get("score", 0))
            * 0.20
        )
        + (
            safe_float(nlp.get("score", 0))
            * 0.10
        )
    )

    # --------------------------------------------------------
    # Unified Risk
    # --------------------------------------------------------

    risk = unified_risk(
        rule_score=rule_score,
        behavior_score=behavior_score_value,
        negative_space_score=negative_space_score,
        peer_score=safe_float(peer.get("score", 0)),
    )

    final_score = safe_float(
        risk.get("score", 0)
    )

    final_risk_level = risk_level(
        final_score
    )

    # --------------------------------------------------------
    # Indicators
    # --------------------------------------------------------

    indicators: list[str] = []

    for item in rules.get("findings", []):
        if isinstance(item, dict):
            message = item.get("message")

            if message:
                indicators.append(
                    str(message)
                )

    for item in gaming.get("indicators", []):
        if item not in indicators:
            indicators.append(
                str(item)
            )

    for item in negative_space:
        if not isinstance(item, dict):
            continue

        category = item.get("category")

        if category:
            indicators.append(
                str(category)
            )

    # Remove duplicates while preserving order.
    indicators = list(
        dict.fromkeys(indicators)
    )

    # --------------------------------------------------------
    # Return complete finding
    # --------------------------------------------------------

    return AnalystFinding(
        analyst_id=str(
            analyst.analyst_id
        ),
        analyst_name=str(
            getattr(
                analyst,
                "name",
                getattr(
                    analyst,
                    "analyst_name",
                    analyst.analyst_id,
                ),
            )
        ),
        rule_score=round_score(
            rule_score
        ),
        behavior_score=round_score(
            behavior_score_value
        ),
        negative_space_score=round_score(
            negative_space_score
        ),
        peer_score=round_score(
            safe_float(
                peer.get("score", 0)
            )
        ),
        score=round_score(
            final_score
        ),
        risk_level=final_risk_level,
        indicators=indicators,
        metrics=metrics,
        rule_findings=rules.get(
            "findings",
            [],
        ),
        investigation_dna=dna,
        gaming_detection=gaming,
        negative_space=negative_space,
        peer_benchmark=peer,
        behavioral=behavior,
        nlp=nlp,
    )

# ============================================================
# Serialization
# ============================================================


def finding_to_dict(
    finding: AnalystFinding,
) -> dict[str, Any]:

    return {
        "analyst_id": finding.analyst_id,
        "analyst_name": finding.analyst_name,

        "score": finding.score,
        "risk_score": finding.score,
        "risk_level": finding.risk_level,

        "components": {
            "rule_score": finding.rule_score,
            "behavior_score": finding.behavior_score,
            "negative_space_score": (
                finding.negative_space_score
            ),
            "peer_score": finding.peer_score,
        },

        "indicators": finding.indicators,

        "metrics": finding.metrics,

        "rule_findings": finding.rule_findings,

        "investigation_dna": finding.investigation_dna,

        "gaming_detection": finding.gaming_detection,

        "negative_space": finding.negative_space,

        "peer_benchmark": finding.peer_benchmark,

        "behavioral": finding.behavioral,

        "nlp": finding.nlp,
    }


# ============================================================
# Main Engine
# ============================================================


def _run_supervisory_analysis() -> dict[str, Any]:

    start = time.perf_counter()

    db: Session = SessionLocal()

    try:

        # ----------------------------------------------------
        # Load
        # ----------------------------------------------------

        (
            analysts,
            alerts,
            investigations,
            assets,
            activities,
        ) = load_data(db)

        load_time = time.perf_counter()

        # ----------------------------------------------------
        # Indexes
        # ----------------------------------------------------

        indexes = build_indexes(
            analysts,
            alerts,
            investigations,
        )

        alerts_by_analyst = indexes[
            "alerts_by_analyst"
        ]

        investigations_by_analyst = indexes[
            "investigations_by_analyst"
        ]

        # ----------------------------------------------------
        # Build all analyst metrics ONCE
        # ----------------------------------------------------

        all_metrics: dict[Any, dict[str, Any]] = {}

        for analyst in analysts:

            analyst_alerts = alerts_by_analyst.get(
                analyst.analyst_id,
                [],
            )

            analyst_investigations = (
                investigations_by_analyst.get(
                    analyst.analyst_id,
                    [],
                )
            )

            all_metrics[
                analyst.analyst_id
            ] = analyst_metrics(
                analyst,
                analyst_alerts,
                analyst_investigations,
            )

        metrics_time = time.perf_counter()

        # ----------------------------------------------------
        # Analyst intelligence
        # ----------------------------------------------------

        findings: list[AnalystFinding] = []

        for analyst in analysts:

            analyst_alerts = alerts_by_analyst.get(
                analyst.analyst_id,
                [],
            )

            analyst_investigations = (
                investigations_by_analyst.get(
                    analyst.analyst_id,
                    [],
                )
            )

            finding = build_finding(
                analyst,
                analyst_alerts,
                analyst_investigations,
                all_metrics,
                assets,
                activities,
            )

            findings.append(
                finding
            )

        analysis_time = time.perf_counter()

        # ----------------------------------------------------
        # Sort
        # ----------------------------------------------------

        findings.sort(
            key=lambda item: item.score,
            reverse=True,
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        risk_counts = Counter(
            finding.risk_level
            for finding in findings
        )

        requiring_attention = [
            finding
            for finding in findings
            if finding.risk_level
            in {
                "HIGH",
                "CRITICAL",
            }
        ]

        average_score = (
            statistics.fmean(
                finding.score
                for finding in findings
            )
            if findings
            else 0.0
        )

        end = time.perf_counter()

        return {
            "engine_version": ENGINE_VERSION,

            "generated_at": datetime.utcnow().isoformat()
            + "Z",

            "summary": {
                "analysts_analyzed": len(
                    analysts
                ),
                "alerts_analyzed": len(
                    alerts
                ),
                "investigations_analyzed": len(
                    investigations
                ),

                "analysts_requiring_attention": len(
                    requiring_attention
                ),

                "average_risk_score": round(
                    average_score,
                    2,
                ),

                "risk_distribution": {
                    "LOW": risk_counts.get(
                        "LOW",
                        0,
                    ),
                    "MEDIUM": risk_counts.get(
                        "MEDIUM",
                        0,
                    ),
                    "HIGH": risk_counts.get(
                        "HIGH",
                        0,
                    ),
                    "CRITICAL": risk_counts.get(
                        "CRITICAL",
                        0,
                    ),
                },
            },

            "performance": {
                "load_seconds": round(
                    load_time - start,
                    4,
                ),
                "metrics_seconds": round(
                    metrics_time - load_time,
                    4,
                ),
                "analysis_seconds": round(
                    analysis_time - metrics_time,
                    4,
                ),
                "total_seconds": round(
                    end - start,
                    4,
                ),
            },

            "findings": [
                finding_to_dict(
                    finding
                )
                for finding in findings
            ],
        }

    finally:

        db.close()


# ============================================================
# Cached Public API
# ============================================================


_ENGINE_CACHE: dict[str, Any] = {
    "result": None,
    "timestamp": 0.0,
}


def run_supervisory_analysis(
    force_refresh: bool = False,
    ttl_seconds: int = DEFAULT_CACHE_TTL,
) -> dict[str, Any]:
    """
    Public entry point.

    Results are cached for a short period so multiple API calls
    do not repeatedly execute the complete intelligence engine.

    Example:

        run_supervisory_analysis()

    Force recalculation:

        run_supervisory_analysis(force_refresh=True)
    """

    now = time.monotonic()

    cached_result = _ENGINE_CACHE.get(
        "result"
    )

    cached_timestamp = safe_float(
        _ENGINE_CACHE.get(
            "timestamp",
            0,
        )
    )

    cache_valid = (
        cached_result is not None
        and (
            now - cached_timestamp
        ) < ttl_seconds
    )

    if (
        not force_refresh
        and cache_valid
    ):
        return cached_result

    result = _run_supervisory_analysis()

    _ENGINE_CACHE["result"] = result
    _ENGINE_CACHE["timestamp"] = time.monotonic()

    return result


def clear_engine_cache() -> None:
    """Clear cached supervisory results."""

    _ENGINE_CACHE["result"] = None
    _ENGINE_CACHE["timestamp"] = 0.0


# ============================================================
# Convenience API Functions
# ============================================================


def get_summary() -> dict[str, Any]:
    return run_supervisory_analysis()[
        "summary"
    ]


def get_findings() -> list[dict[str, Any]]:
    return run_supervisory_analysis()[
        "findings"
    ]


def get_analyst_findings() -> list[dict[str, Any]]:
    return get_findings()


def get_analyst_finding(
    analyst_id: str,
) -> dict[str, Any] | None:

    findings = get_findings()

    for finding in findings:

        if str(
            finding["analyst_id"]
        ) == str(analyst_id):

            return finding

    return None


# ============================================================
# CLI
# ============================================================


def print_engine_summary(
    result: dict[str, Any],
) -> None:

    summary = result["summary"]

    performance = result[
        "performance"
    ]

    print()
    print("=" * 70)
    print("SAT-SA SUPERVISORY INTELLIGENCE ENGINE")
    print("=" * 70)

    print(
        f"Engine Version: "
        f"{result['engine_version']}"
    )

    print(
        f"Analysts analyzed: "
        f"{summary['analysts_analyzed']}"
    )

    print(
        f"Alerts analyzed: "
        f"{summary['alerts_analyzed']}"
    )

    print(
        f"Investigations analyzed: "
        f"{summary['investigations_analyzed']}"
    )

    print(
        f"Analysts requiring attention: "
        f"{summary['analysts_requiring_attention']}"
    )

    print(
        f"Average risk score: "
        f"{summary['average_risk_score']}"
    )

    print()
    print("RISK DISTRIBUTION")

    for level, count in (
        summary["risk_distribution"]
    ).items():

        print(
            f"  {level:<10} {count}"
        )

    print()
    print("TOP 10 SUPERVISORY FINDINGS")

    for index, finding in enumerate(
        result["findings"][:10],
        start=1,
    ):

        print(
            f"\n{index}. "
            f"{finding['analyst_id']} - "
            f"{finding['analyst_name']}"
        )

        print(
            f"   Risk: "
            f"{finding['score']}/100 "
            f"{finding['risk_level']}"
        )

        metrics = finding[
            "metrics"
        ]

        print(
            f"   Alerts: "
            f"{metrics['alert_count']}"
        )

        print(
            f"   Avg closure: "
            f"{metrics['average_closure_time']}"
        )

        print(
            f"   Evidence: "
            f"{metrics['evidence_review_rate']}%"
        )

        if finding["indicators"]:

            print(
                "   Indicators: "
                + "; ".join(
                    finding["indicators"][:5]
                )
            )

    print()
    print("PERFORMANCE")

    print(
        f"  Load:     "
        f"{performance['load_seconds']}s"
    )

    print(
        f"  Metrics:  "
        f"{performance['metrics_seconds']}s"
    )

    print(
        f"  Analysis: "
        f"{performance['analysis_seconds']}s"
    )

    print(
        f"  Total:    "
        f"{performance['total_seconds']}s"
    )

    print("=" * 70)
    print()


if __name__ == "__main__":

    result = run_supervisory_analysis(
        force_refresh=True
    )

    print_engine_summary(
        result
    )