"""
anomaly_model.py
================

Unsupervised anomaly scorer. This is the FIRST line of defense in the
pipeline: it needs no labels, so it works from day one (cold start at
the *system* level, not just the user level) and can in principle catch
attack patterns we never explicitly labeled.

Default: scikit-learn IsolationForest (fast, robust, no scaling
required, handles mixed-scale numeric features well). An optional
Keras/TF autoencoder is stubbed below behind the same interface if you
want to swap it in later -- it's commented out so this module has zero
extra dependencies out of the box.

Score convention used throughout this project: HIGHER = more anomalous,
scaled roughly to [0, 1] via a min-max squashing of IsolationForest's
raw `score_samples` output, so it's directly usable as a "risk score" in
the dashboard without extra explanation.
"""

from __future__ import annotations
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
from features.feature_engineering import FEATURE_NAMES


class AnomalyScorer:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 300, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._fit_scores_min = None
        self._fit_scores_max = None
        self.feature_names = FEATURE_NAMES

    def _to_matrix(self, feature_rows: list[dict]) -> np.ndarray:
        df = pd.DataFrame(feature_rows)[self.feature_names]
        return df.values.astype(float)

    def fit(self, feature_rows: list[dict]):
        X = self._to_matrix(feature_rows)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        # Calibrate the min/max of raw scores on the training set so we
        # can squash future scores into a stable [0, 1] risk range.
        raw = self.model.score_samples(Xs)
        self._fit_scores_min = float(raw.min())
        self._fit_scores_max = float(raw.max())
        return self

    def _squash(self, raw_scores: np.ndarray) -> np.ndarray:
        # IsolationForest score_samples: LOWER = more anomalous. We flip
        # sign and min-max scale (clipped) so output is HIGHER = riskier,
        # in [0, 1].
        lo, hi = self._fit_scores_min, self._fit_scores_max
        span = (hi - lo) if hi > lo else 1e-6
        norm = (raw_scores - lo) / span  # in ~[0,1], higher = more normal
        norm = np.clip(norm, 0.0, 1.0)
        return 1.0 - norm  # higher = more anomalous

    def score(self, feature_rows: list[dict]) -> np.ndarray:
        X = self._to_matrix(feature_rows)
        Xs = self.scaler.transform(X)
        raw = self.model.score_samples(Xs)
        return self._squash(raw)

    def predict_is_anomaly(self, feature_rows: list[dict], threshold: float = 0.6) -> np.ndarray:
        return self.score(feature_rows) >= threshold


# ---------------------------------------------------------------------------
# Optional: Keras autoencoder variant behind the same interface.
# Uncomment and `pip install tensorflow` if you want reconstruction-error
# based scoring instead of / in addition to IsolationForest for the demo.
# ---------------------------------------------------------------------------
#
# class AutoencoderScorer:
#     def __init__(self, encoding_dim: int = 6, epochs: int = 30):
#         from tensorflow import keras
#         from tensorflow.keras import layers
#         self.epochs = epochs
#         self.scaler = StandardScaler()
#         self.encoding_dim = encoding_dim
#         self.model = None
#         self.feature_names = FEATURE_NAMES
#         self._threshold = None
#
#     def _build(self, input_dim):
#         from tensorflow import keras
#         from tensorflow.keras import layers
#         inp = keras.Input(shape=(input_dim,))
#         x = layers.Dense(max(4, input_dim // 2), activation="relu")(inp)
#         x = layers.Dense(self.encoding_dim, activation="relu")(x)
#         x = layers.Dense(max(4, input_dim // 2), activation="relu")(x)
#         out = layers.Dense(input_dim, activation="linear")(x)
#         model = keras.Model(inp, out)
#         model.compile(optimizer="adam", loss="mse")
#         return model
#
#     def fit(self, feature_rows):
#         X = pd.DataFrame(feature_rows)[self.feature_names].values.astype(float)
#         Xs = self.scaler.fit_transform(X)
#         self.model = self._build(Xs.shape[1])
#         self.model.fit(Xs, Xs, epochs=self.epochs, batch_size=64, verbose=0)
#         recon = self.model.predict(Xs, verbose=0)
#         errs = np.mean((Xs - recon) ** 2, axis=1)
#         self._err_min, self._err_max = float(errs.min()), float(errs.max())
#         return self
#
#     def score(self, feature_rows):
#         X = pd.DataFrame(feature_rows)[self.feature_names].values.astype(float)
#         Xs = self.scaler.transform(X)
#         recon = self.model.predict(Xs, verbose=0)
#         errs = np.mean((Xs - recon) ** 2, axis=1)
#         span = (self._err_max - self._err_min) or 1e-6
#         return np.clip((errs - self._err_min) / span, 0.0, 1.0)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "../features")
    sys.path.insert(0, "../data")
    from features.feature_engineering import build_feature_table
    import csv
    from datetime import datetime

    events = []
    with open("../data/sample_logs.csv") as f:
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
    scorer = AnomalyScorer(contamination=0.05).fit(feature_rows)
    scores = scorer.score(feature_rows)

    import numpy as np
    labels_arr = np.array(labels)
    for lbl in sorted(set(labels)):
        mask = labels_arr == lbl
        print(f"{lbl:20s} n={mask.sum():5d}  mean_score={scores[mask].mean():.3f}")