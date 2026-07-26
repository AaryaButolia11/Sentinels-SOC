from __future__ import annotations
import numpy as np
from anomaly_model import AnomalyScorer


def test_scores_are_bounded_and_higher_is_riskier(feature_table):
    feature_rows, labels, _ = feature_table
    scorer = AnomalyScorer(contamination=0.05).fit(feature_rows)
    scores = scorer.score(feature_rows)

    assert scores.min() >= 0.0
    assert scores.max() <= 1.0

    labels_arr = np.array(labels)
    normal_mean = scores[labels_arr == "none"].mean()
    attack_mask = labels_arr != "none"
    if attack_mask.any():
        attack_mean = scores[attack_mask].mean()
        # attacks should on average look riskier than normal traffic --
        # this is the whole point of the unsupervised first stage
        assert attack_mean > normal_mean


def test_predict_is_anomaly_matches_threshold(feature_table):
    feature_rows, _, _ = feature_table
    scorer = AnomalyScorer(contamination=0.05).fit(feature_rows)
    scores = scorer.score(feature_rows)
    flags = scorer.predict_is_anomaly(feature_rows, threshold=0.6)
    assert (flags == (scores >= 0.6)).all()