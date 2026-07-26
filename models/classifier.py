"""
classifier.py
=============

Supervised attack-type classifier. Runs ONLY on events the anomaly
scorer already flagged as suspicious (score > threshold) -- this is a
two-stage design on purpose:

  Stage 1 (anomaly_model.py, unsupervised): "is this weird at all?"
           Catches novel/unlabeled attack patterns too.
  Stage 2 (this file, supervised):          "given that it's weird,
           which of our known attack types does it most resemble?"

Using LightGBM here (falls back to sklearn's GradientBoosting if
LightGBM isn't installed) because it's fast, handles the mixed-scale
numeric features from feature_engineering.py natively, and has
first-class SHAP support for explainability.py.
"""

from __future__ import annotations
import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
from features.feature_engineering import FEATURE_NAMES
from models.imbalance import compute_class_weights, sample_weights_from_class_weights, apply_smote

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    from sklearn.ensemble import GradientBoostingClassifier


class AttackClassifier:
    """Multi-class classifier over attack types (excludes 'none' -- that
    class is handled upstream by the anomaly scorer's threshold, not by
    this classifier, since 'none' dominates the label distribution and
    isn't itself an "attack type" to predict)."""

    def __init__(self, use_smote: bool = True, random_state: int = 42):
        self.use_smote = use_smote
        self.random_state = random_state
        self.label_encoder = LabelEncoder()
        self.feature_names = FEATURE_NAMES
        self.model = None
        self.classes_ = None

    def _to_matrix(self, feature_rows: list[dict]) -> np.ndarray:
        return pd.DataFrame(feature_rows)[self.feature_names].values.astype(float)

    def fit(self, feature_rows: list[dict], labels: list[str], test_size: float = 0.25):
        """Trains only on rows whose label != 'none' (attack rows)."""
        df_feats = pd.DataFrame(feature_rows)[self.feature_names]
        labels_arr = np.array(labels)
        attack_mask = labels_arr != "none"

        X_attacks = df_feats.values[attack_mask].astype(float)
        y_attacks = labels_arr[attack_mask]

        y_enc = self.label_encoder.fit_transform(y_attacks)
        self.classes_ = self.label_encoder.classes_

        X_train, X_test, y_train, y_test = train_test_split(
            X_attacks, y_enc, test_size=test_size, random_state=self.random_state,
            stratify=y_enc if len(set(y_enc)) > 1 else None,
        )

        # class weights computed on the *string* labels for readability,
        # then mapped onto the encoded training split
        y_train_labels = self.label_encoder.inverse_transform(y_train)
        class_weights_str = compute_class_weights(y_train_labels)
        class_weights_enc = {
            self.label_encoder.transform([k])[0]: v for k, v in class_weights_str.items()
        }

        if self.use_smote:
            y_train_labels_for_smote = self.label_encoder.inverse_transform(y_train)
            X_train, y_train_labels_res = apply_smote(X_train, y_train_labels_for_smote, smote_min_samples=25)
            y_train = self.label_encoder.transform(y_train_labels_res)

        sample_weight = np.array([class_weights_enc.get(label, 1.0) for label in y_train])

        if HAS_LIGHTGBM:
            self.model = lgb.LGBMClassifier(
                objective="multiclass",
                num_class=len(self.classes_),
                n_estimators=300,
                learning_rate=0.05,
                max_depth=6,
                random_state=self.random_state,
                verbosity=-1,
            )
            self.model.fit(X_train, y_train, sample_weight=sample_weight)
        else:
            self.model = GradientBoostingClassifier(random_state=self.random_state)
            self.model.fit(X_train, y_train, sample_weight=sample_weight)

        self._X_test, self._y_test = X_test, y_test
        return self

    def evaluate(self) -> dict:
        y_pred = self.model.predict(self._X_test)
        report = classification_report(
            self._y_test, y_pred, target_names=self.classes_, output_dict=True, zero_division=0
        )
        precision, recall, f1, _ = precision_recall_fscore_support(
            self._y_test, y_pred, average="macro", zero_division=0
        )
        return {
            "per_class_report": report,
            "macro_precision": precision,
            "macro_recall": recall,
            "macro_f1": f1,
        }

    def predict(self, feature_rows: list[dict]) -> list[str]:
        X = self._to_matrix(feature_rows)
        preds = self.model.predict(X)
        return list(self.label_encoder.inverse_transform(preds))

    def predict_proba(self, feature_rows: list[dict]) -> pd.DataFrame:
        X = self._to_matrix(feature_rows)
        proba = self.model.predict_proba(X)
        return pd.DataFrame(proba, columns=self.classes_)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
    from features.feature_engineering import build_feature_table
    import csv
    from datetime import datetime

    events = []
    with open(os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")) as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["resource_sensitivity"] = int(row["resource_sensitivity"])
            row["geo_lat"] = float(row["geo_lat"])
            row["geo_lon"] = float(row["geo_lon"])
            row["session_duration_s"] = (
                int(row["session_duration_s"]) if row["session_duration_s"] not in ("", "None") else None
            )
            events.append(row)

    feature_rows, labels, store = build_feature_table(events)

    clf = AttackClassifier(use_smote=True).fit(feature_rows, labels)
    results = clf.evaluate()
    print(f"Using LightGBM: {HAS_LIGHTGBM}")
    print(f"Macro precision: {results['macro_precision']:.3f}")
    print(f"Macro recall:    {results['macro_recall']:.3f}")
    print(f"Macro F1:        {results['macro_f1']:.3f}")
    print()
    for cls in clf.classes_:
        m = results["per_class_report"][cls]
        print(f"  {cls:20s} precision={m['precision']:.2f} recall={m['recall']:.2f} "
              f"f1={m['f1-score']:.2f} support={int(m['support'])}")