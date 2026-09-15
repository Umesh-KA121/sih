"""
SAT-SA Supervisory Intelligence Engine

Combines:

A. Analytics
B. Rule intelligence
C. Investigation DNA
D. Negative-space detection
E. Gaming detection
F. Peer benchmarking
G. Behavioral anomaly detection
H. Lightweight NLP
I. Unified risk engine

The engine is intentionally dependency-light so the backend can run
without NumPy / SciPy / scikit-learn native extensions.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from statistics import mean, median, pstdev
from typing import Any

from sqlalchemy import inspect, text

from app.database import engine


# ============================================================
# Configuration
# ============================================================

RULE_WEIGHT = 0.40
BEHAVIOR_WEIGHT = 0.30
NEGATIVE_SPACE_WEIGHT = 0.20
PEER_WEIGHT = 0.10

RISK_THRESHOLDS = {
    "LOW": 39,
    "MEDIUM": 70,
    "HIGH": 89,
}


# ============================================================
# Generic helpers
# ============================================================

def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0

    return numerator / denominator


def percentile(values: list[float], p: float) -> float:
    """
    Lightweight percentile implementation.

    p is expected between 0 and 100.
    """
    if not values:
        return 0.0

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    position = (len(values) - 1) * (p / 100.0)
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return values[lower]

    weight = position - lower

    return (
        values[lower] * (1 - weight)
        + values[upper] * weight
    )


def z_score(value: float, values: list[float]) -> float:
    if len(values) < 2:
        return 0.0

    deviation = pstdev(values)

    if deviation == 0:
        return 0.0

    return (value - mean(values)) / deviation


def normalize_text(value: Any) -> str:
    if value is None:
        return ""

    text_value = str(value).lower()

    text_value = re.sub(
        r"[^a-z0-9\s]",
        " ",
        text_value,
    )

    text_value = re.sub(
        r"\s+",
        " ",
        text_value,
    )

    return text_value.strip()


def tokenize(value: Any) -> set[str]:
    text_value = normalize_text(value)

    if not text_value:
        return set()

    stop_words = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "to",
        "of",
        "in",
        "on",
        "for",
        "is",
        "was",
        "were",
        "with",
        "this",
        "that",
        "no",
        "not",
    }

    return {
        token
        for token in text_value.split()
        if token not in stop_words
        and len(token) >= 3
    }


def jaccard_similarity(
    first: set[str],
    second: set[str],
) -> float:
    if not first or not second:
        return 0.0

    union = first | second

    if not union:
        return 0.0

    return len(first & second) / len(union)


def action_count(value: Any) -> int:
    if not value:
        return 0

    return len(
        [
            item
            for item in str(value).split(";")
            if item.strip()
        ]
    )


# ============================================================
# Database reflection
# ============================================================

def table_columns(table_name: str) -> set[str]:
    inspector = inspect(engine)

    try:
        return {
            column["name"]
            for column in inspector.get_columns(table_name)
        }
    except Exception:
        return set()


def first_existing(
    columns: set[str],
    candidates: list[str],
) -> str | None:
    for candidate in candidates:
        if candidate in columns:
            return candidate

    return None


# ============================================================
# Data loading
# ============================================================

def load_core_data() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """
    Load analysts, alerts and investigations.

    Only required fields are selected.
    """

    with engine.connect() as connection:

        analysts = [
            dict(row._mapping)
            for row in connection.execute(
                text(
                    """
                    SELECT
                        analyst_id,
                        organization_id,
                        name,
                        role,
                        team,
                        experience_years,
                        shift,
                        status
                    FROM analysts
                    """
                )
            )
        ]

        alerts = [
            dict(row._mapping)
            for row in connection.execute(
                text(
                    """
                    SELECT
                        alert_id,
                        external_id,
                        organization_id,
                        asset_id,
                        analyst_id,
                        alert_type,
                        severity,
                        status,
                        created_at,
                        closed_at,
                        closure_time_minutes,
                        investigation_notes,
                        evidence_reviewed,
                        escalated,
                        false_positive,
                        incident_id
                    FROM alerts
                    """
                )
            )
        ]

        investigations = [
            dict(row._mapping)
            for row in connection.execute(
                text(
                    """
                    SELECT
                        investigation_id,
                        alert_id,
                        analyst_id,
                        started_at,
                        completed_at,
                        duration_minutes,
                        actions_performed,
                        queries_executed,
                        evidence_reviewed,
                        investigation_notes,
                        findings,
                        escalation_decision
                    FROM investigations
                    """
                )
            )
        ]

    return analysts, alerts, investigations


# ============================================================
# PHASE A
# Feature Builder
# ============================================================

def build_features(
    analysts: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    investigations: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:

    features: dict[str, dict[str, Any]] = {
        analyst["analyst_id"]: {
            "analyst_id": analyst["analyst_id"],
            "name": analyst.get("name"),
            "organization_id": analyst.get("organization_id"),
            "role": analyst.get("role"),
            "team": analyst.get("team"),
            "experience_years": analyst.get("experience_years"),
            "shift": analyst.get("shift"),
            "status": analyst.get("status"),

            "alerts": [],
            "investigations": [],

            "total_alerts": 0,
            "closed_alerts": 0,
            "critical_alerts": 0,
            "critical_closed": 0,

            "escalated_alerts": 0,
            "false_positive_alerts": 0,
            "evidence_reviewed_alerts": 0,

            "closure_times": [],

            "investigation_count": 0,
            "investigation_durations": [],
            "query_counts": [],
            "action_counts": [],
            "evidence_reviewed_investigations": 0,
            "escalated_investigations": 0,

            "notes": [],
            "findings": [],
        }
        for analyst in analysts
    }

    for alert in alerts:

        analyst_id = alert.get("analyst_id")

        if analyst_id not in features:
            continue

        item = features[analyst_id]

        item["alerts"].append(alert)

        item["total_alerts"] += 1

        if str(alert.get("status", "")).lower() == "closed":
            item["closed_alerts"] += 1

        if str(alert.get("severity", "")).lower() == "critical":
            item["critical_alerts"] += 1

            if str(alert.get("status", "")).lower() == "closed":
                item["critical_closed"] += 1

        if alert.get("escalated"):
            item["escalated_alerts"] += 1

        if alert.get("false_positive"):
            item["false_positive_alerts"] += 1

        if alert.get("evidence_reviewed"):
            item["evidence_reviewed_alerts"] += 1

        closure = alert.get("closure_time_minutes")

        if closure is not None:
            item["closure_times"].append(
                safe_float(closure)
            )

        if alert.get("investigation_notes"):
            item["notes"].append(
                str(alert["investigation_notes"])
            )

    for investigation in investigations:

        analyst_id = investigation.get("analyst_id")

        if analyst_id not in features:
            continue

        item = features[analyst_id]

        item["investigations"].append(investigation)

        item["investigation_count"] += 1

        duration = investigation.get("duration_minutes")

        if duration is not None:
            item["investigation_durations"].append(
                safe_float(duration)
            )

        queries = investigation.get("queries_executed")

        if queries is not None:
            item["query_counts"].append(
                safe_float(queries)
            )

        item["action_counts"].append(
            action_count(
                investigation.get("actions_performed")
            )
        )

        if investigation.get("evidence_reviewed"):
            item["evidence_reviewed_investigations"] += 1

        if (
            str(
                investigation.get(
                    "escalation_decision",
                    "",
                )
            ).lower()
            == "yes"
        ):
            item["escalated_investigations"] += 1

        if investigation.get("investigation_notes"):
            item["notes"].append(
                str(
                    investigation[
                        "investigation_notes"
                    ]
                )
            )

        if investigation.get("findings"):
            item["findings"].append(
                str(
                    investigation["findings"]
                )
            )

    return features


# ============================================================
# PHASE B
# Rule Intelligence
# ============================================================

def run_rules(
    feature: dict[str, Any],
) -> dict[str, Any]:

    total_alerts = feature["total_alerts"]
    closed_alerts = feature["closed_alerts"]

    critical_alerts = feature["critical_alerts"]

    avg_closure = (
        mean(feature["closure_times"])
        if feature["closure_times"]
        else 0.0
    )

    evidence_rate = (
        ratio(
            feature["evidence_reviewed_alerts"],
            total_alerts,
        )
        * 100
        if total_alerts
        else 0.0
    )

    escalation_rate = (
        ratio(
            feature["escalated_alerts"],
            total_alerts,
        )
        * 100
        if total_alerts
        else 0.0
    )

    avg_queries = (
        mean(feature["query_counts"])
        if feature["query_counts"]
        else 0.0
    )

    avg_actions = (
        mean(feature["action_counts"])
        if feature["action_counts"]
        else 0.0
    )

    avg_duration = (
        mean(feature["investigation_durations"])
        if feature["investigation_durations"]
        else 0.0
    )

    triggered = []
    points = 0

    # --------------------------------------------------------
    # FAST_CLOSURE
    # --------------------------------------------------------

    if (
        critical_alerts >= 1
        and closed_alerts >= 1
        and avg_closure < 10
    ):
        triggered.append(
            {
                "rule": "FAST_CLOSURE",
                "title": "Suspiciously fast closure",
                "score": 25,
                "reason": (
                    f"Critical alerts are being closed in "
                    f"an average of {avg_closure:.1f} minutes."
                ),
            }
        )

        points += 25

    # --------------------------------------------------------
    # SHORT_NOTES
    # --------------------------------------------------------

    note_lengths = [
        len(normalize_text(note).split())
        for note in feature["notes"]
        if normalize_text(note)
    ]

    avg_note_length = (
        mean(note_lengths)
        if note_lengths
        else 0.0
    )

    if (
        note_lengths
        and avg_note_length < 20
    ):
        triggered.append(
            {
                "rule": "SHORT_NOTES",
                "title": "Investigation notes are unusually short",
                "score": 15,
                "reason": (
                    f"Average investigation note length is "
                    f"{avg_note_length:.1f} words."
                ),
            }
        )

        points += 15

    # --------------------------------------------------------
    # NO_EVIDENCE
    # --------------------------------------------------------

    if (
        total_alerts >= 5
        and evidence_rate < 50
    ):
        triggered.append(
            {
                "rule": "NO_EVIDENCE",
                "title": "Low evidence-review rate",
                "score": 20,
                "reason": (
                    f"Only {evidence_rate:.1f}% of alerts "
                    f"have evidence review recorded."
                ),
            }
        )

        points += 20

    # --------------------------------------------------------
    # NO_ESCALATION
    # --------------------------------------------------------

    if (
        critical_alerts >= 5
        and escalation_rate < 10
    ):
        triggered.append(
            {
                "rule": "NO_ESCALATION",
                "title": "Critical alerts rarely escalated",
                "score": 15,
                "reason": (
                    f"{critical_alerts} critical alerts observed "
                    f"with only {escalation_rate:.1f}% escalation."
                ),
            }
        )

        points += 15

    # --------------------------------------------------------
    # ABNORMAL_HANDLING
    # --------------------------------------------------------

    if (
        feature["investigation_count"] >= 5
        and avg_queries < 2
        and avg_actions < 2
        and avg_duration < 10
    ):
        triggered.append(
            {
                "rule": "ABNORMAL_HANDLING",
                "title": "Very shallow investigation handling",
                "score": 20,
                "reason": (
                    "Investigations show low query activity, "
                    "low action activity and short duration."
                ),
            }
        )

        points += 20

    return {
        "score": clamp(points),
        "rules_triggered": triggered,
    }


# ============================================================
# PHASE C + H
# Investigation DNA / Lightweight NLP
# ============================================================

def analyze_investigation_dna(
    feature: dict[str, Any],
) -> dict[str, Any]:

    investigations = feature["investigations"]

    if not investigations:
        return {
            "quality_score": 0.0,
            "note_similarity": 0.0,
            "note_repetition_rate": 0.0,
            "evidence_discipline": 0.0,
            "investigation_depth": 0.0,
            "query_activity": 0.0,
            "action_activity": 0.0,
            "note_quality": 0.0,
            "closure_behavior": 0.0,
            "signals": [],
        }

    signals = []

    # --------------------------------------------------------
    # Evidence discipline
    # --------------------------------------------------------

    evidence_rate = (
        ratio(
            feature[
                "evidence_reviewed_investigations"
            ],
            len(investigations),
        )
        * 100
    )

    # --------------------------------------------------------
    # Query activity
    # --------------------------------------------------------

    avg_queries = (
        mean(feature["query_counts"])
        if feature["query_counts"]
        else 0.0
    )

    query_score = clamp(
        avg_queries / 10 * 100
    )

    # --------------------------------------------------------
    # Action activity
    # --------------------------------------------------------

    avg_actions = (
        mean(feature["action_counts"])
        if feature["action_counts"]
        else 0.0
    )

    action_score = clamp(
        avg_actions / 8 * 100
    )

    # --------------------------------------------------------
    # Investigation depth
    # --------------------------------------------------------

    avg_duration = (
        mean(feature["investigation_durations"])
        if feature["investigation_durations"]
        else 0.0
    )

    depth_score = clamp(
        (
            min(avg_duration / 60, 1.0) * 50
            + min(avg_queries / 5, 1.0) * 25
            + min(avg_actions / 4, 1.0) * 25
        )
    )

    # --------------------------------------------------------
    # NLP note quality
    # --------------------------------------------------------

    notes = [
        normalize_text(note)
        for note in feature["notes"]
        if normalize_text(note)
    ]

    note_lengths = [
        len(note.split())
        for note in notes
    ]

    avg_note_length = (
        mean(note_lengths)
        if note_lengths
        else 0.0
    )

    evidence_keywords = {
        "evidence",
        "log",
        "logs",
        "ip",
        "source",
        "endpoint",
        "authentication",
        "query",
        "event",
        "process",
        "timeline",
        "reviewed",
        "correlated",
        "verified",
    }

    finding_keywords = {
        "finding",
        "conclusion",
        "determined",
        "confirmed",
        "observed",
        "identified",
        "malicious",
        "benign",
        "escalated",
        "resolved",
    }

    evidence_hits = 0
    finding_hits = 0

    for note in notes:

        tokens = set(note.split())

        if tokens & evidence_keywords:
            evidence_hits += 1

        if tokens & finding_keywords:
            finding_hits += 1

    evidence_reference_rate = (
        ratio(evidence_hits, len(notes))
        * 100
        if notes
        else 0.0
    )

    finding_rate = (
        ratio(finding_hits, len(notes))
        * 100
        if notes
        else 0.0
    )

    length_score = clamp(
        min(avg_note_length / 80, 1.0)
        * 100
    )

    specificity_score = (
        evidence_reference_rate * 0.6
        + finding_rate * 0.4
    )

    note_quality = (
        length_score * 0.35
        + specificity_score * 0.65
    )

    # --------------------------------------------------------
    # Similarity / repetition
    # --------------------------------------------------------

    normalized_counter = Counter(notes)

    duplicate_notes = sum(
        count - 1
        for count in normalized_counter.values()
        if count > 1
    )

    repetition_rate = (
        ratio(
            duplicate_notes,
            len(notes),
        )
        * 100
        if notes
        else 0.0
    )

    similarity_values = []

    # Only compare a bounded number of notes.
    # This avoids O(N²) over huge datasets.
    candidate_notes = notes[:200]

    for index in range(len(candidate_notes)):

        first = tokenize(
            candidate_notes[index]
        )

        for other_index in range(
            index + 1,
            len(candidate_notes),
        ):

            second = tokenize(
                candidate_notes[other_index]
            )

            similarity_values.append(
                jaccard_similarity(
                    first,
                    second,
                )
            )

    avg_similarity = (
        mean(similarity_values)
        if similarity_values
        else 0.0
    )

    # --------------------------------------------------------
    # Closure behaviour
    # --------------------------------------------------------

    avg_closure = (
        mean(feature["closure_times"])
        if feature["closure_times"]
        else 0.0
    )

    closure_score = clamp(
        100 - (avg_closure / 60 * 100)
    )

    # --------------------------------------------------------
    # Overall investigation quality
    # --------------------------------------------------------

    quality_score = (
        evidence_rate * 0.20
        + depth_score * 0.20
        + query_score * 0.10
        + action_score * 0.10
        + note_quality * 0.25
        + (100 - repetition_rate) * 0.10
        + (100 - closure_score) * 0.05
    )

    if repetition_rate >= 40:
        signals.append(
            "High investigation-note repetition"
        )

    if evidence_rate < 50:
        signals.append(
            "Weak evidence discipline"
        )

    if avg_note_length < 20:
        signals.append(
            "Low narrative depth"
        )

    if avg_queries < 2:
        signals.append(
            "Low query activity"
        )

    if avg_actions < 2:
        signals.append(
            "Low action activity"
        )

    if avg_duration < 10:
        signals.append(
            "Very short investigations"
        )

    return {
        "quality_score": round(
            clamp(quality_score),
            2,
        ),
        "note_similarity": round(
            avg_similarity * 100,
            2,
        ),
        "note_repetition_rate": round(
            repetition_rate,
            2,
        ),
        "evidence_discipline": round(
            evidence_rate,
            2,
        ),
        "investigation_depth": round(
            depth_score,
            2,
        ),
        "query_activity": round(
            query_score,
            2,
        ),
        "action_activity": round(
            action_score,
            2,
        ),
        "note_quality": round(
            note_quality,
            2,
        ),
        "closure_behavior": round(
            closure_score,
            2,
        ),
        "signals": signals,
    }


# ============================================================
# PHASE E
# Gaming Detection
# ============================================================

def detect_gaming(
    feature: dict[str, Any],
    dna: dict[str, Any],
) -> dict[str, Any]:

    signals = []
    score = 0

    # Repeated notes
    repetition = dna["note_repetition_rate"]

    if repetition >= 40:
        score += 35

        signals.append(
            "Repeated investigation notes"
        )

    # Repeated closure durations
    closures = [
        round(value, 0)
        for value in feature["closure_times"]
    ]

    if len(closures) >= 5:

        counter = Counter(closures)

        most_common = counter.most_common(1)[0]

        repeated_count = most_common[1]

        if (
            repeated_count / len(closures)
            >= 0.50
        ):
            score += 25

            signals.append(
                "Suspiciously uniform closure durations"
            )

    # Shallow + fast workflow
    avg_duration = (
        mean(
            feature["investigation_durations"]
        )
        if feature["investigation_durations"]
        else 0
    )

    avg_queries = (
        mean(feature["query_counts"])
        if feature["query_counts"]
        else 0
    )

    avg_actions = (
        mean(feature["action_counts"])
        if feature["action_counts"]
        else 0
    )

    if (
        avg_duration < 10
        and avg_queries < 2
        and avg_actions < 2
    ):
        score += 30

        signals.append(
            "Fast closure combined with shallow investigation"
        )

    # High closure + weak investigation
    closure_rate = ratio(
        feature["closed_alerts"],
        feature["total_alerts"],
    ) * 100

    if (
        closure_rate >= 90
        and dna["quality_score"] < 40
    ):
        score += 20

        signals.append(
            "High closure rate with weak investigation quality"
        )

    return {
        "score": clamp(score),
        "signals": signals,
    }


# ============================================================
# PHASE G
# Behavioral Analytics
# ============================================================

def build_behavior_baseline(
    features: dict[str, dict[str, Any]],
) -> dict[str, list[float]]:

    closure_values = []
    duration_values = []
    query_values = []
    evidence_values = []

    for feature in features.values():

        if feature["closure_times"]:
            closure_values.append(
                mean(feature["closure_times"])
            )

        if feature["investigation_durations"]:
            duration_values.append(
                mean(
                    feature[
                        "investigation_durations"
                    ]
                )
            )

        if feature["query_counts"]:
            query_values.append(
                mean(feature["query_counts"])
            )

        if feature["total_alerts"]:
            evidence_values.append(
                ratio(
                    feature[
                        "evidence_reviewed_alerts"
                    ],
                    feature["total_alerts"],
                )
                * 100
            )

    return {
        "closure": closure_values,
        "duration": duration_values,
        "queries": query_values,
        "evidence": evidence_values,
    }


def behavioral_score(
    feature: dict[str, Any],
    baseline: dict[str, list[float]],
) -> dict[str, Any]:

    deviations = []
    signals = []

    # --------------------------------------------------------
    # Closure deviation
    # --------------------------------------------------------

    if feature["closure_times"]:

        current = mean(
            feature["closure_times"]
        )

        values = baseline["closure"]

        z = abs(
            z_score(
                current,
                values,
            )
        )

        deviations.append(
            min(z / 3 * 100, 100)
        )

        if z >= 2:
            signals.append(
                "Closure behavior deviates from analyst baseline"
            )

    # --------------------------------------------------------
    # Investigation duration deviation
    # --------------------------------------------------------

    if feature["investigation_durations"]:

        current = mean(
            feature[
                "investigation_durations"
            ]
        )

        values = baseline["duration"]

        z = abs(
            z_score(
                current,
                values,
            )
        )

        deviations.append(
            min(z / 3 * 100, 100)
        )

        if z >= 2:
            signals.append(
                "Investigation duration deviates from baseline"
            )

    # --------------------------------------------------------
    # Query deviation
    # --------------------------------------------------------

    if feature["query_counts"]:

        current = mean(
            feature["query_counts"]
        )

        values = baseline["queries"]

        z = abs(
            z_score(
                current,
                values,
            )
        )

        deviations.append(
            min(z / 3 * 100, 100)
        )

        if z >= 2:
            signals.append(
                "Query activity deviates from baseline"
            )

    # --------------------------------------------------------
    # Evidence deviation
    # --------------------------------------------------------

    if feature["total_alerts"]:

        current = (
            ratio(
                feature[
                    "evidence_reviewed_alerts"
                ],
                feature["total_alerts"],
            )
            * 100
        )

        values = baseline["evidence"]

        z = abs(
            z_score(
                current,
                values,
            )
        )

        deviations.append(
            min(z / 3 * 100, 100)
        )

        if z >= 2:
            signals.append(
                "Evidence-review behavior deviates from baseline"
            )

    score = (
        mean(deviations)
        if deviations
        else 0.0
    )

    return {
        "score": round(
            clamp(score),
            2,
        ),
        "signals": signals,
    }


# ============================================================
# PHASE D
# Negative Space
# ============================================================

def negative_space_analysis() -> dict[str, Any]:

    """
    Detect assets that are important but have unusually little
    or zero security activity.

    The engine dynamically adapts to the actual asset_activity
    schema generated by the project.
    """

    columns = table_columns(
        "asset_activity"
    )

    asset_columns = table_columns(
        "assets"
    )

    if not asset_columns:
        return {
            "score": 0.0,
            "findings": [],
            "signals": [],
        }

    asset_id_column = first_existing(
        asset_columns,
        [
            "asset_id",
            "id",
        ],
    )

    if not asset_id_column:
        return {
            "score": 0.0,
            "findings": [],
            "signals": [],
        }

    criticality_column = first_existing(
        asset_columns,
        [
            "criticality",
            "criticality_level",
            "priority",
            "risk_level",
        ],
    )

    name_column = first_existing(
        asset_columns,
        [
            "name",
            "asset_name",
            "hostname",
        ],
    )

    if not columns:

        # Fall back to alert silence.
        with engine.connect() as connection:

            query = f"""
                SELECT
                    a.{asset_id_column} AS asset_id,
                    {f'a.{name_column}' if name_column else 'NULL'} AS asset_name,
                    COUNT(al.alert_id) AS alert_count
                FROM assets a
                LEFT JOIN alerts al
                    ON CAST(al.asset_id AS TEXT)
                    = CAST(a.{asset_id_column} AS TEXT)
                GROUP BY
                    a.{asset_id_column}
                    {f', a.{name_column}' if name_column else ''}
                HAVING COUNT(al.alert_id) = 0
                LIMIT 200
            """

            rows = [
                dict(row._mapping)
                for row in connection.execute(
                    text(query)
                )
            ]

        findings = []

        for row in rows:

            findings.append(
                {
                    "asset_id": row["asset_id"],
                    "asset_name": row.get(
                        "asset_name"
                    ),
                    "reason": (
                        "Asset has no associated "
                        "security alerts."
                    ),
                    "severity": "Medium",
                }
            )

        score = min(
            len(findings) * 5,
            100,
        )

        return {
            "score": score,
            "findings": findings,
            "signals": (
                ["Critical asset silence detected"]
                if findings
                else []
            ),
        }

    # --------------------------------------------------------
    # asset_activity exists
    # --------------------------------------------------------

    activity_asset_column = first_existing(
        columns,
        [
            "asset_id",
            "asset",
        ],
    )

    if not activity_asset_column:
        return {
            "score": 0.0,
            "findings": [],
            "signals": [],
        }

    activity_count_column = first_existing(
        columns,
        [
            "activity_count",
            "event_count",
            "events",
            "count",
        ],
    )

    if activity_count_column:

        query = f"""
            SELECT
                CAST({activity_asset_column} AS TEXT)
                    AS asset_id,
                SUM(
                    COALESCE(
                        CAST({activity_count_column} AS NUMERIC),
                        0
                    )
                ) AS activity_count
            FROM asset_activity
            GROUP BY {activity_asset_column}
        """

    else:

        query = f"""
            SELECT
                CAST({activity_asset_column} AS TEXT)
                    AS asset_id,
                COUNT(*) AS activity_count
            FROM asset_activity
            GROUP BY {activity_asset_column}
        """

    with engine.connect() as connection:

        activity_rows = [
            dict(row._mapping)
            for row in connection.execute(
                text(query)
            )
        ]

    activity_by_asset = {
        str(row["asset_id"]): safe_float(
            row["activity_count"]
        )
        for row in activity_rows
    }

    findings = []

    # Find low-activity assets.
    activity_values = list(
        activity_by_asset.values()
    )

    if activity_values:

        silence_threshold = percentile(
            activity_values,
            10,
        )

        for asset_id, count in activity_by_asset.items():

            if count <= silence_threshold:

                findings.append(
                    {
                        "asset_id": asset_id,
                        "activity_count": count,
                        "reason": (
                            "Asset activity is in the "
                            "lowest 10% of observed assets."
                        ),
                        "severity": "Medium",
                    }
                )

    score = min(
        len(findings) * 3,
        100,
    )

    return {
        "score": round(score, 2),
        "findings": findings[:200],
        "signals": (
            ["Negative-space activity anomaly detected"]
            if findings
            else []
        ),
    }


# ============================================================
# PHASE F
# Peer Benchmark
# ============================================================

def peer_benchmark_scores(
    features: dict[str, dict[str, Any]],
) -> dict[str, float]:

    organization_metrics: dict[
        str,
        dict[str, list[float]],
    ] = defaultdict(
        lambda: {
            "closure": [],
            "evidence": [],
            "escalation": [],
            "duration": [],
        }
    )

    for feature in features.values():

        organization_id = feature[
            "organization_id"
        ]

        if not organization_id:
            continue

        if feature["closure_times"]:
            organization_metrics[
                organization_id
            ]["closure"].append(
                mean(feature["closure_times"])
            )

        if feature["total_alerts"]:

            organization_metrics[
                organization_id
            ]["evidence"].append(
                ratio(
                    feature[
                        "evidence_reviewed_alerts"
                    ],
                    feature["total_alerts"],
                )
                * 100
            )

            organization_metrics[
                organization_id
            ]["escalation"].append(
                ratio(
                    feature[
                        "escalated_alerts"
                    ],
                    feature["total_alerts"],
                )
                * 100
            )

        if feature["investigation_durations"]:

            organization_metrics[
                organization_id
            ]["duration"].append(
                mean(
                    feature[
                        "investigation_durations"
                    ]
                )
            )

    # Convert organizations into peer distributions.
    organization_values = defaultdict(list)

    for organization_id, metrics in (
        organization_metrics.items()
    ):

        for metric_name, values in metrics.items():

            if values:
                organization_values[
                    metric_name
                ].append(
                    mean(values)
                )

    result = {
        analyst_id: 0.0
        for analyst_id in features
    }

    for analyst_id, feature in features.items():

        organization_id = feature[
            "organization_id"
        ]

        if organization_id not in organization_metrics:
            continue

        deviations = []

        org_metrics = organization_metrics[
            organization_id
        ]

        for metric_name, current_values in (
            [
                (
                    "closure",
                    feature["closure_times"],
                ),
                (
                    "evidence",
                    (
                        [
                            ratio(
                                feature[
                                    "evidence_reviewed_alerts"
                                ],
                                feature[
                                    "total_alerts"
                                ],
                            )
                            * 100
                        ]
                        if feature["total_alerts"]
                        else []
                    ),
                ),
                (
                    "escalation",
                    (
                        [
                            ratio(
                                feature[
                                    "escalated_alerts"
                                ],
                                feature[
                                    "total_alerts"
                                ],
                            )
                            * 100
                        ]
                        if feature["total_alerts"]
                        else []
                    ),
                ),
                (
                    "duration",
                    feature[
                        "investigation_durations"
                    ],
                ),
            ]
        ):

            if not current_values:
                continue

            current = mean(current_values)

            peer_values = (
                organization_values[
                    metric_name
                ]
            )

            if len(peer_values) < 2:
                continue

            deviation = abs(
                z_score(
                    current,
                    peer_values,
                )
            )

            deviations.append(
                min(
                    deviation / 3 * 100,
                    100,
                )
            )

        if deviations:
            result[analyst_id] = round(
                mean(deviations),
                2,
            )

    return result


# ============================================================
# PHASE I
# Unified Risk Engine
# ============================================================

def risk_level(score: float) -> str:

    score = clamp(score)

    if score >= 90:
        return "CRITICAL"

    if score > 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def unified_risk(
    rule_score: float,
    behavior_score: float,
    negative_space_score: float,
    peer_score: float,
) -> dict[str, Any]:

    final_score = (
        rule_score * RULE_WEIGHT
        + behavior_score * BEHAVIOR_WEIGHT
        + negative_space_score * NEGATIVE_SPACE_WEIGHT
        + peer_score * PEER_WEIGHT
    )

    return {
        "score": round(
            clamp(final_score),
            2,
        ),
        "level": risk_level(
            final_score
        ),
        "components": {
            "rule_score": round(
                clamp(rule_score),
                2,
            ),
            "behavior_score": round(
                clamp(behavior_score),
                2,
            ),
            "negative_space_score": round(
                clamp(negative_space_score),
                2,
            ),
            "peer_score": round(
                clamp(peer_score),
                2,
            ),
        },
        "weights": {
            "rule": RULE_WEIGHT,
            "behavior": BEHAVIOR_WEIGHT,
            "negative_space": NEGATIVE_SPACE_WEIGHT,
            "peer": PEER_WEIGHT,
        },
    }


# ============================================================
# Finding generation
# ============================================================

def generate_finding(
    feature: dict[str, Any],
    rules: dict[str, Any],
    dna: dict[str, Any],
    gaming: dict[str, Any],
    behavior: dict[str, Any],
    peer_score: float,
    negative_space_score: float,
    risk: dict[str, Any],
) -> dict[str, Any] | None:

    signals = []

    for item in rules["rules_triggered"]:
        signals.append(
            item["reason"]
        )

    signals.extend(
        dna["signals"]
    )

    signals.extend(
        gaming["signals"]
    )

    signals.extend(
        behavior["signals"]
    )

    if negative_space_score > 0:
        signals.append(
            "Negative-space anomaly detected"
        )

    if peer_score >= 50:
        signals.append(
            "Behavior deviates significantly from peers"
        )

    if not signals and risk["score"] < 40:
        return None

    # Evidence references
    alert_ids = [
        alert.get("alert_id")
        for alert in feature["alerts"][:25]
        if alert.get("alert_id")
    ]

    investigation_ids = [
        investigation.get(
            "investigation_id"
        )
        for investigation in feature[
            "investigations"
        ][:25]
        if investigation.get(
            "investigation_id"
        )
    ]

    title = (
        "SOC analyst behavior requires supervisory review"
    )

    if any(
        item["rule"] == "FAST_CLOSURE"
        for item in rules["rules_triggered"]
    ):
        title = (
            "Suspiciously fast critical-alert handling"
        )

    elif dna["note_repetition_rate"] >= 40:
        title = (
            "Investigation-note repetition detected"
        )

    elif gaming["score"] >= 50:
        title = (
            "Potential SOC workflow gaming detected"
        )

    return {
        "finding_id": (
            f"F-{feature['analyst_id']}-"
            f"{int(risk['score'] * 100)}"
        ),
        "type": "ANALYST_BEHAVIOR",
        "severity": risk["level"],
        "risk_score": risk["score"],
        "title": title,
        "description": (
            "SAT-SA identified behavioral or investigation "
            "characteristics that differ from expected SOC "
            "operational patterns."
        ),
        "analyst_id": feature["analyst_id"],
        "analyst_name": feature["name"],
        "organization_id": feature[
            "organization_id"
        ],
        "indicators": signals[:15],
        "evidence": {
            "alert_ids": alert_ids,
            "investigation_ids": investigation_ids,
            "total_alerts": feature[
                "total_alerts"
            ],
            "critical_alerts": feature[
                "critical_alerts"
            ],
        },
        "scores": {
            "rule_score": rules["score"],
            "investigation_quality": dna[
                "quality_score"
            ],
            "gaming_score": gaming[
                "score"
            ],
            "behavior_score": behavior[
                "score"
            ],
            "negative_space_score": negative_space_score,
            "peer_score": peer_score,
        },
        "recommendation": (
            "Review the affected alerts and investigation "
            "records, validate evidence handling, compare "
            "the analyst against team peers, and determine "
            "whether the observed pattern represents a "
            "process gap or legitimate operational behavior."
        ),
    }


# ============================================================
# Main engine
# ============================================================

def run_supervisory_analysis() -> dict[str, Any]:

    analysts, alerts, investigations = (
        load_core_data()
    )

    features = build_features(
        analysts,
        alerts,
        investigations,
    )

    baseline = build_behavior_baseline(
        features
    )

    peer_scores = peer_benchmark_scores(
        features
    )

    negative_space = (
        negative_space_analysis()
    )

    analyst_results = []
    findings = []

    for analyst_id, feature in features.items():

        rules = run_rules(feature)

        dna = analyze_investigation_dna(
            feature
        )

        gaming = detect_gaming(
            feature,
            dna,
        )

        behavior = behavioral_score(
            feature,
            baseline,
        )

        # AI / Behavior combines:
        # investigation DNA + gaming + behavioral deviation
        behavior_score = clamp(
            dna["quality_score"] * 0.35
            + gaming["score"] * 0.30
            + behavior["score"] * 0.35
        )

        risk = unified_risk(
            rule_score=rules["score"],
            behavior_score=behavior_score,
            negative_space_score=negative_space[
                "score"
            ],
            peer_score=peer_scores.get(
                analyst_id,
                0.0,
            ),
        )

        result = {
            "analyst_id": analyst_id,
            "name": feature["name"],
            "organization_id": feature[
                "organization_id"
            ],
            "role": feature["role"],
            "team": feature["team"],
            "risk": risk,

            "rules": rules,

            "investigation_dna": dna,

            "gaming_detection": gaming,

            "behavior": {
                **behavior,
                "combined_ai_behavior_score": round(
                    behavior_score,
                    2,
                ),
            },

            "peer": {
                "score": peer_scores.get(
                    analyst_id,
                    0.0,
                )
            },

            "metrics": {
                "total_alerts": feature[
                    "total_alerts"
                ],
                "closed_alerts": feature[
                    "closed_alerts"
                ],
                "critical_alerts": feature[
                    "critical_alerts"
                ],
                "critical_closed": feature[
                    "critical_closed"
                ],
                "evidence_review_rate": round(
                    ratio(
                        feature[
                            "evidence_reviewed_alerts"
                        ],
                        feature[
                            "total_alerts"
                        ],
                    ) * 100,
                    2,
                )
                if feature["total_alerts"]
                else 0.0,
                "escalation_rate": round(
                    ratio(
                        feature[
                            "escalated_alerts"
                        ],
                        feature[
                            "total_alerts"
                        ],
                    ) * 100,
                    2,
                )
                if feature["total_alerts"]
                else 0.0,
            },
        }

        analyst_results.append(
            result
        )

        finding = generate_finding(
            feature=feature,
            rules=rules,
            dna=dna,
            gaming=gaming,
            behavior=behavior,
            peer_score=peer_scores.get(
                analyst_id,
                0.0,
            ),
            negative_space_score=negative_space[
                "score"
            ],
            risk=risk,
        )

        if finding:
            findings.append(
                finding
            )

    # --------------------------------------------------------
    # Negative-space findings
    # --------------------------------------------------------

    for item in negative_space[
        "findings"
    ][:100]:

        findings.append(
            {
                "finding_id": (
                    f"NEG-{item['asset_id']}"
                ),
                "type": "NEGATIVE_SPACE",
                "severity": item.get(
                    "severity",
                    "MEDIUM",
                ).upper(),
                "risk_score": round(
                    negative_space["score"],
                    2,
                ),
                "title": (
                    "Asset monitoring gap detected"
                ),
                "description": (
                    "An asset shows unexpectedly low or "
                    "absent security activity."
                ),
                "asset_id": item[
                    "asset_id"
                ],
                "indicators": [
                    item["reason"]
                ],
                "evidence": item,
                "recommendation": (
                    "Verify asset monitoring, telemetry "
                    "collection, detection coverage and "
                    "logging configuration."
                ),
            }
        )

    # Highest risk first
    analyst_results.sort(
        key=lambda item: item[
            "risk"
        ]["score"],
        reverse=True,
    )

    findings.sort(
        key=lambda item: item[
            "risk_score"
        ],
        reverse=True,
    )

    # --------------------------------------------------------
    # Dashboard summary
    # --------------------------------------------------------

    risk_distribution = Counter(
        item["risk"]["level"]
        for item in analyst_results
    )

    overall_health = (
        100
        - mean(
            [
                item["risk"]["score"]
                for item in analyst_results
            ]
        )
        if analyst_results
        else 100
    )

    return {
        "engine": "SAT-SA Supervisory Intelligence Engine",
        "dataset": {
            "analysts": len(analysts),
            "alerts": len(alerts),
            "investigations": len(
                investigations
            ),
        },
        "overall_health": round(
            clamp(overall_health),
            2,
        ),
        "risk_distribution": dict(
            risk_distribution
        ),
        "negative_space": negative_space,
        "analysts": analyst_results,
        "findings": findings,
        "finding_count": len(findings),
        "high_priority_findings": [
            finding
            for finding in findings
            if finding["severity"]
            in {
                "HIGH",
                "CRITICAL",
            }
        ][:100],
    }


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    result = run_supervisory_analysis()

    print()
    print("=" * 72)
    print("SAT-SA SUPERVISORY INTELLIGENCE ENGINE")
    print("=" * 72)

    print(
        f"Analysts:       "
        f"{result['dataset']['analysts']}"
    )

    print(
        f"Alerts:         "
        f"{result['dataset']['alerts']}"
    )

    print(
        f"Investigations: "
        f"{result['dataset']['investigations']}"
    )

    print(
        f"Overall health: "
        f"{result['overall_health']}/100"
    )

    print(
        f"Findings:       "
        f"{result['finding_count']}"
    )

    print()
    print("Risk distribution:")

    for level, count in sorted(
        result["risk_distribution"].items()
    ):
        print(
            f"  {level:<10} {count}"
        )

    print()
    print("TOP FINDINGS")
    print("-" * 72)

    for finding in result[
        "findings"
    ][:10]:

        print(
            f"\n{finding['severity']} | "
            f"{finding['risk_score']}"
        )

        print(
            finding["title"]
        )

        if finding.get(
            "analyst_name"
        ):
            print(
                f"Analyst: "
                f"{finding['analyst_name']}"
            )

        for indicator in finding[
            "indicators"
        ][:3]:
            print(
                f"  - {indicator}"
            )