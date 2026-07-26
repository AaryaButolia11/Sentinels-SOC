"""
evaluate.py
===========
One-shot evaluation of the whole detector on data/sample_logs.csv.

Reports, for every metric that matters:

  STAGE 1  (unsupervised AnomalyScorer)
    - mean/std risk score per class (separation check)
    - ROC-AUC for "attack vs normal" using the raw risk score
    - precision / recall / F1 / confusion at the operating threshold

  STAGE 2  (supervised AttackClassifier, attacks only)
    - macro precision / recall / F1
    - full per-class precision / recall / F1 / support
    - confusion matrix on the held-out test split

  END-TO-END (anomaly gate -> classifier), replayed like production
    - how many attacks the two-stage system actually catches & names

Run from the project root:
    python evaluate.py
    python evaluate.py --data data/sample_logs.csv --threshold 0.6
"""
from __future__ import annotations
import argparse
import csv
import os
import sys
from datetime import datetime

import numpy as np

# make sibling packages importable (same trick conftest/sitecustomize use)
ROOT = os.path.dirname(os.path.abspath(__file__))
for sub in ("", "data", "features", "models", "streaming", "api"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from features.feature_engineering import build_feature_table, FEATURE_NAMES
from models.anomaly_model import AnomalyScorer
from models.classifier import AttackClassifier, HAS_LIGHTGBM

from sklearn.metrics import (
    roc_auc_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["resource_sensitivity"] = int(row["resource_sensitivity"])
            row["geo_lat"] = float(row["geo_lat"])
            row["geo_lon"] = float(row["geo_lon"])
            row["session_duration_s"] = (
                int(row["session_duration_s"])
                if row["session_duration_s"] not in ("", "None")
                else None
            )
            events.append(row)
    return events


def hr(title: str):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def evaluate_anomaly_stage(feature_rows, labels, threshold: float):
    hr("STAGE 1 — Unsupervised anomaly scorer (IsolationForest)")
    scorer = AnomalyScorer(contamination=0.05).fit(feature_rows)
    scores = scorer.score(feature_rows)
    labels_arr = np.array(labels)

    # per-class score separation
    print(f"\n{'class':20s} {'n':>6s} {'mean_risk':>10s} {'std':>8s} {'min':>6s} {'max':>6s}")
    print("-" * 60)
    for lbl in sorted(set(labels)):
        m = labels_arr == lbl
        s = scores[m]
        print(f"{lbl:20s} {m.sum():6d} {s.mean():10.3f} {s.std():8.3f} {s.min():6.2f} {s.max():6.2f}")

    # binary attack-vs-normal quality of the raw score
    y_bin = (labels_arr != "none").astype(int)
    if y_bin.sum() and y_bin.sum() < len(y_bin):
        auc = roc_auc_score(y_bin, scores)
        print(f"\nROC-AUC (attack vs normal, raw risk score): {auc:.4f}")

        # at the operating threshold
        flags = (scores >= threshold).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(
            y_bin, flags, average="binary", zero_division=0
        )
        cm = confusion_matrix(y_bin, flags)
        print(f"\nAt threshold = {threshold}:")
        print(f"  precision (of flagged, how many were attacks): {p:.3f}")
        print(f"  recall    (of attacks, how many were flagged): {r:.3f}")
        print(f"  F1                                            : {f1:.3f}")
        print(f"  confusion [rows=truth none/attack, cols=pred none/attack]:")
        print("   ", cm.tolist())
    return scores


def evaluate_classifier_stage(feature_rows, labels):
    hr(f"STAGE 2 — Supervised attack classifier (LightGBM={HAS_LIGHTGBM})")
    clf = AttackClassifier(use_smote=True).fit(feature_rows, labels)
    results = clf.evaluate()

    print(f"\nHeld-out macro metrics (25% test split, attacks only):")
    print(f"  macro precision : {results['macro_precision']:.4f}")
    print(f"  macro recall    : {results['macro_recall']:.4f}")
    print(f"  macro F1        : {results['macro_f1']:.4f}")

    print(f"\n{'class':20s} {'precision':>10s} {'recall':>8s} {'f1':>8s} {'support':>8s}")
    print("-" * 58)
    for cls in clf.classes_:
        m = results["per_class_report"][cls]
        print(f"{cls:20s} {m['precision']:10.3f} {m['recall']:8.3f} "
              f"{m['f1-score']:8.3f} {int(m['support']):8d}")

    # confusion matrix on the held-out split
    y_pred = clf.model.predict(clf._X_test)
    cm = confusion_matrix(clf._y_test, y_pred)
    print(f"\nConfusion matrix (rows=truth, cols=pred), class order:")
    print("  " + ", ".join(f"{i}={c}" for i, c in enumerate(clf.classes_)))
    for i, rowvals in enumerate(cm.tolist()):
        print(f"  {i} {clf.classes_[i]:18s} {rowvals}")
    return clf


def evaluate_end_to_end(events, threshold: float):
    """Replay every event through both stages in time order, exactly like
    the live pipeline, and measure the two-stage system as a whole."""
    hr(f"END-TO-END — two-stage replay (gate @ {threshold} -> classify)")

    # train on first 80%, evaluate on the held-out 20% "live" slice
    split = int(len(events) * 0.8)
    train_events, live_events = events[:split], events[split:]

    train_rows, train_labels, store = build_feature_table(train_events)
    scorer = AnomalyScorer(contamination=0.05).fit(train_rows)
    clf = AttackClassifier(use_smote=True).fit(train_rows, train_labels)

    from features.feature_engineering import compute_features, population_baseline
    from features.cold_start import ColdStartBlender
    blender = ColdStartBlender()
    population = population_baseline(store.profiles)

    n_attack = n_caught = n_named = 0
    per_type = {}
    for ev in live_events:
        feats = compute_features(ev, store, population, blender)
        risk = float(scorer.score([feats])[0])
        truth = ev.get("label", "none")
        is_attack = truth != "none"
        if is_attack:
            n_attack += 1
            per_type.setdefault(truth, [0, 0, 0])  # [total, caught, named-correct]
            per_type[truth][0] += 1
        if risk >= threshold:
            if is_attack:
                n_caught += 1
                per_type[truth][1] += 1
                pred = clf.predict([feats])[0]
                if pred == truth:
                    n_named += 1
                    per_type[truth][2] += 1
        store.update(ev)

    print(f"\nLive slice: {len(live_events)} events, {n_attack} true attacks")
    if n_attack:
        print(f"  caught by anomaly gate : {n_caught}/{n_attack} = {n_caught/n_attack:.1%} recall")
        print(f"  correctly named        : {n_named}/{n_attack} = {n_named/n_attack:.1%} of all attacks")
    print(f"\n  {'attack type':20s} {'total':>6s} {'caught':>7s} {'named':>6s}")
    print("  " + "-" * 42)
    for t, (tot, caught, named) in sorted(per_type.items()):
        print(f"  {t:20s} {tot:6d} {caught:7d} {named:6d}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(ROOT, "data", "sample_logs.csv"))
    ap.add_argument("--threshold", type=float, default=0.6,
                    help="anomaly risk threshold used as the classify gate")
    args = ap.parse_args()

    if not os.path.exists(args.data):
        raise SystemExit(
            f"No data at {args.data}. Generate it first:\n"
            f"  python data/generate_logs.py --out data/sample_logs.csv"
        )

    events = load_events(args.data)
    print(f"Loaded {len(events)} events from {args.data}")
    from collections import Counter
    print("Label distribution:", dict(Counter(e.get("label", "none") for e in events)))

    feature_rows, labels, _ = build_feature_table(events)

    evaluate_anomaly_stage(feature_rows, labels, args.threshold)
    evaluate_classifier_stage(feature_rows, labels)
    evaluate_end_to_end(events, args.threshold)

    print("\n" + "=" * 72)
    print("NOTE: near-perfect scores on this SYNTHETIC data are expected — the")
    print("injected attacks have deliberately distinct signatures. Treat these")
    print("as a wiring/sanity check, not a real-world accuracy claim.")
    print("=" * 72)


if __name__ == "__main__":
    main()