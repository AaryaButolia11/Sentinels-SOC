"""
pipeline.py
===========

Orchestrates the full per-event flow:

    event -> features -> anomaly score -> (if suspicious) classify
          -> explain -> Alert object

This is the one place that stitches together features/, models/, so
both the FastAPI backend and stream_simulator.py can just call
`Pipeline.process(event)` and get an Alert (or None if the event is
routine, in which case no alert is stored -- only score+features are
kept if you want them for later drift analysis).
"""

from __future__ import annotations
import os
import sys
import uuid
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))

from features.user_profiles import ProfileStore, population_baseline
from features.cold_start import ColdStartBlender
from features.feature_engineering import compute_features, FEATURE_NAMES
from models.anomaly_model import AnomalyScorer
from models.classifier import AttackClassifier
from models.explainability import explain_classifier, explain_anomaly, fit_population_stats


@dataclass
class Alert:
    alert_id: str
    event: dict
    risk_score: float
    predicted_label: Optional[str]
    label_confidence: Optional[float]
    explanation: dict
    analyst_verdict: Optional[str] = None  # filled in later by feedback.py


class Pipeline:
    def __init__(self, anomaly_threshold: float = 0.6):
        self.store = ProfileStore()
        self.blender = ColdStartBlender()
        self.anomaly_scorer: Optional[AnomalyScorer] = None
        self.classifier: Optional[AttackClassifier] = None
        self.anomaly_threshold = anomaly_threshold
        self._population = {"n_events_total": 0, "hour_histogram": {}, "resource_histogram": {}}
        self._feature_means, self._feature_stds = {}, {}

    def fit(self, feature_rows: list[dict], labels: list[str], store: ProfileStore):
        """Train both models on a historical batch, and keep the same
        ProfileStore so live events continue building on real history
        instead of starting cold."""
        self.store = store
        self._population = population_baseline(store.profiles)
        self.anomaly_scorer = AnomalyScorer(contamination=0.05).fit(feature_rows)
        self.classifier = AttackClassifier(use_smote=True).fit(feature_rows, labels)
        self._feature_means, self._feature_stds = fit_population_stats(feature_rows, FEATURE_NAMES)
        return self

    def process(self, event: dict) -> Optional[Alert]:
        """Score ONE live event. IMPORTANT: features are computed before
        store.update(), matching feature_engineering.py's ordering rule."""
        feats = compute_features(event, self.store, self._population, self.blender)
        risk_score = float(self.anomaly_scorer.score([feats])[0])

        alert = None
        if risk_score >= self.anomaly_threshold:
            pred_label = self.classifier.predict([feats])[0]
            proba = self.classifier.predict_proba([feats]).iloc[0]
            confidence = float(proba.max())

            try:
                explanation = explain_classifier(self.classifier.model, feats, FEATURE_NAMES)
            except Exception:
                explanation = explain_anomaly(feats, self._feature_means, self._feature_stds)

            alert = Alert(
                alert_id=str(uuid.uuid4()),
                event=event,
                risk_score=risk_score,
                predicted_label=pred_label,
                label_confidence=confidence,
                explanation=explanation,
            )

        # Update baseline AFTER scoring so the event never leaks into its
        # own comparison (per feature_engineering.py's ordering rule).
        self.store.update(event)
        return alert


if __name__ == "__main__":
    import csv
    from datetime import datetime

    def load_events(path):
        events = []
        with open(path) as f:
            for row in csv.DictReader(f):
                row["timestamp"] = datetime.fromisoformat(row["timestamp"])
                row["resource_sensitivity"] = int(row["resource_sensitivity"])
                row["geo_lat"] = float(row["geo_lat"])
                row["geo_lon"] = float(row["geo_lon"])
                row["session_duration_s"] = (
                    int(row["session_duration_s"]) if row["session_duration_s"] not in ("", "None") else None
                )
                events.append(row)
        return events

    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")
    all_events = load_events(data_path)

    # Train on the first 80% "historical" chunk, then replay the last
    # 20% as "live" events through the pipeline one at a time.
    split = int(len(all_events) * 0.8)
    train_events, live_events = all_events[:split], all_events[split:]

    from features.feature_engineering import build_feature_table
    feature_rows, labels, store = build_feature_table(train_events)

    pipeline = Pipeline(anomaly_threshold=0.6).fit(feature_rows, labels, store)

    n_alerts = 0
    for ev in live_events:
        alert = pipeline.process(ev)
        if alert:
            n_alerts += 1
            if n_alerts <= 5:
                print(f"[ALERT] user={ev['user_id']} true_label={ev.get('label')} "
                      f"risk={alert.risk_score:.2f} predicted={alert.predicted_label} "
                      f"({alert.label_confidence:.2f} conf)")
                print(f"        {alert.explanation['sentence']}")

    print(f"\nProcessed {len(live_events)} live events, raised {n_alerts} alerts.")