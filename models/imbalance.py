"""
imbalance.py
============

Attack classes are rare by construction (that's the whole point -- a
"brute_force" rate of 30% would mean your baseline detection already
failed). Left alone, a classifier trained on this data will just learn
to always predict "none" and still score ~97% accuracy while being
useless. This module offers two complementary strategies:

  1. Class weighting (cheap, always-on): inversely weight each class by
     its frequency so rare attack types contribute proportionally more
     to the loss. Works natively with LightGBM's `class_weight` /
     `sample_weight`.

  2. SMOTE oversampling (optional, applied only to the TRAINING split):
     synthesizes new minority-class samples by interpolating between
     real minority samples' feature vectors. Useful when a class has so
     few examples that per-class weighting alone doesn't give the
     model enough signal to learn a decision boundary.

Rule of thumb used here: classes with fewer than `smote_min_samples`
examples in the training split get SMOTE'd up to a reasonable floor;
everything is additionally class-weighted regardless.
"""

from __future__ import annotations
import numpy as np
from collections import Counter


def compute_class_weights(y: np.ndarray) -> dict:
    """Inverse-frequency class weights, normalized so the average
    weight across classes is ~1.0 (keeps loss scale comparable to
    unweighted training)."""
    counts = Counter(y)
    n_classes = len(counts)
    n_total = len(y)
    weights = {cls: n_total / (n_classes * cnt) for cls, cnt in counts.items()}
    return weights


def sample_weights_from_class_weights(y: np.ndarray, class_weights: dict) -> np.ndarray:
    return np.array([class_weights[label] for label in y])


def apply_smote(X: np.ndarray, y: np.ndarray, smote_min_samples: int = 30,
                 k_neighbors: int = 3, random_state: int = 42):
    """Oversample minority classes with SMOTE, but only for classes that
    are thin enough to need it (avoids over-synthesizing classes that
    already have reasonable support, which can introduce noise).

    Falls back gracefully if a class has fewer than k_neighbors+1
    samples (SMOTE needs enough neighbors to interpolate between).
    """
    from imblearn.over_sampling import SMOTE

    counts = Counter(y)
    target_classes = {cls: cnt for cls, cnt in counts.items() if cnt < smote_min_samples}
    if not target_classes:
        return X, y  # nothing thin enough to need it

    sampling_strategy = {}
    for cls, cnt in target_classes.items():
        if cnt <= k_neighbors:
            # too few samples to interpolate safely; skip SMOTE for this
            # class and rely on class weighting instead
            continue
        sampling_strategy[cls] = smote_min_samples

    if not sampling_strategy:
        return X, y

    safe_k = min(k_neighbors, min(sampling_strategy_count - 1 for sampling_strategy_count in
                                   [counts[c] for c in sampling_strategy]) or 1)
    safe_k = max(1, safe_k)

    smote = SMOTE(sampling_strategy=sampling_strategy, k_neighbors=safe_k, random_state=random_state)
    X_res, y_res = smote.fit_resample(X, y)
    return X_res, y_res


if __name__ == "__main__":
    y = np.array(["none"] * 900 + ["brute_force"] * 60 + ["device_spoofing"] * 6 + ["impossible_travel"] * 8)
    print("Raw counts:", Counter(y))
    print("Class weights:", compute_class_weights(y))

    X = np.random.randn(len(y), 5)
    X_res, y_res = apply_smote(X, y, smote_min_samples=30)
    print("After SMOTE:", Counter(y_res))