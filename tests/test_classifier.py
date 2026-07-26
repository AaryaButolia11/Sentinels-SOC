from __future__ import annotations
from classifier import AttackClassifier


def test_classifier_trains_and_excludes_none_class(feature_table):
    feature_rows, labels, _ = feature_table
    clf = AttackClassifier(use_smote=True).fit(feature_rows, labels)
    assert "none" not in set(clf.classes_)
    assert len(clf.classes_) > 0


def test_predict_returns_known_labels(feature_table):
    feature_rows, labels, _ = feature_table
    clf = AttackClassifier(use_smote=True).fit(feature_rows, labels)
    preds = clf.predict(feature_rows[:20])
    assert all(p in set(clf.classes_) for p in preds)


def test_evaluate_returns_macro_metrics(feature_table):
    feature_rows, labels, _ = feature_table
    clf = AttackClassifier(use_smote=True).fit(feature_rows, labels)
    results = clf.evaluate()
    for key in ("macro_precision", "macro_recall", "macro_f1"):
        assert 0.0 <= results[key] <= 1.0