"""
SAT-SA Analyst Anomaly Detection

Uses Isolation Forest to detect unusual analyst behavior
from behavioral metrics already calculated by SAT-SA.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# -------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------

CONTAMINATION = 0.05
RANDOM_STATE = 42


# -------------------------------------------------------------------
# FEATURE EXTRACTION
# -------------------------------------------------------------------

def build_feature_matrix(analysts: list[dict[str, Any]]) -> np.ndarray:
    """
    Convert analyst metric dictionaries into an ML feature matrix.

    Each row represents one analyst.
    Each column represents one behavioral feature.
    """

    features = []

    for analyst in analysts:
        features.append(
            [
                float(analyst.get("total_alerts", 0)),
                float(analyst.get("avg_closure_time", 0)),
                float(analyst.get("evidence_review_rate", 0)),
                float(analyst.get("escalation_rate", 0)),
                float(analyst.get("total_investigations", 0)),
                float(analyst.get("avg_queries", 0)),
                float(analyst.get("avg_investigation_time", 0)),
            ]
        )

    if not features:
        return np.empty((0, 7))

    return np.array(features, dtype=float)


# -------------------------------------------------------------------
# ANOMALY DETECTION
# -------------------------------------------------------------------

def detect_anomalies(
    analysts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Detect unusual analyst behavior using Isolation Forest.

    Returns the original analyst records with:
        anomaly_score
        is_anomaly
    """

    if not analysts:
        return []

    feature_matrix = build_feature_matrix(analysts)

    if len(feature_matrix) < 2:
        for analyst in analysts:
            analyst["anomaly_score"] = 0.0
            analyst["is_anomaly"] = False

        return analysts

    # Standardize features so that large numeric ranges do not
    # dominate the anomaly detector.
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(feature_matrix)

    # Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(scaled_features)

    # sklearn:
    #   prediction = -1 -> anomaly
    #   prediction =  1 -> normal
    predictions = model.predict(scaled_features)

    # decision_function:
    # larger value = more normal
    # smaller value = more anomalous
    raw_scores = model.decision_function(scaled_features)

    # Convert to an easy-to-understand 0-100 anomaly score.
    min_score = raw_scores.min()
    max_score = raw_scores.max()

    if max_score == min_score:
        anomaly_scores = np.zeros(len(raw_scores))
    else:
        anomaly_scores = (
            (max_score - raw_scores)
            / (max_score - min_score)
            * 100
        )

    for index, analyst in enumerate(analysts):
        analyst["anomaly_score"] = round(
            float(anomaly_scores[index]),
            2,
        )

        analyst["is_anomaly"] = bool(
            predictions[index] == -1
        )

    return analysts


# -------------------------------------------------------------------
# DEMO / TEST
# -------------------------------------------------------------------

if __name__ == "__main__":

    sample_analysts = [
        {
            "analyst_id": "AN001",
            "total_alerts": 20,
            "avg_closure_time": 45,
            "evidence_review_rate": 90,
            "escalation_rate": 30,
            "total_investigations": 20,
            "avg_queries": 8,
            "avg_investigation_time": 40,
        },
        {
            "analyst_id": "AN002",
            "total_alerts": 18,
            "avg_closure_time": 40,
            "evidence_review_rate": 85,
            "escalation_rate": 25,
            "total_investigations": 18,
            "avg_queries": 7,
            "avg_investigation_time": 35,
        },
        {
            "analyst_id": "AN003",
            "total_alerts": 2,
            "avg_closure_time": 3,
            "evidence_review_rate": 0,
            "escalation_rate": 0,
            "total_investigations": 2,
            "avg_queries": 1,
            "avg_investigation_time": 4,
        },
    ]

    results = detect_anomalies(sample_analysts)

    print("\nSAT-SA ML ANOMALY DETECTION")
    print("=" * 70)

    for analyst in results:
        print(
            f"{analyst['analyst_id']} | "
            f"Anomaly Score: {analyst['anomaly_score']:.2f} | "
            f"Anomaly: {analyst['is_anomaly']}"
        )