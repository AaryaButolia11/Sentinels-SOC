"""
explainability.py
==================

Turns SHAP values into a short plain-English sentence an analyst can
read in under 2 seconds, instead of a bar chart they have to interpret.

Two explain paths:
  - explain_classifier(): SHAP TreeExplainer on the LightGBM attack
    classifier (only called on events already flagged anomalous).
  - explain_anomaly(): a lightweight "z-score style" fallback that
    explains the IsolationForest score even with no attack-type label
    yet (works for genuinely novel/unknown patterns the classifier
    was never trained on).

Both return the same shape: {"top_features": [...], "sentence": "..."}
so the API/dashboard don't need to care which path produced it.
"""

from __future__ import annotations
import numpy as np
import pandas as pd

# Human-readable templates per feature. Keep these short + specific;
# judges remember one good sentence, not five vague ones.
FEATURE_PHRASES = {
    "hour_typicality": "logged in at an hour this user rarely uses ({value:.2f} typicality)",
    "is_new_device": "used a device never seen for this user before",
    "is_new_country": "connected from a country never seen for this user before",
    "device_familiarity": "used an unfamiliar device (low familiarity score)",
    "resource_sensitivity": "touched a high-sensitivity resource (level {value:.0f}/5)",
    "resource_familiarity": "accessed a resource this user almost never touches",
    "geo_distance_from_home_km": "was {value:.0f} km from this user's usual home location",
    "geo_velocity_kmh": "implied a travel speed of {value:.0f} km/h since the last login (physically implausible)",
    "seconds_since_last_event": "occurred only {value:.0f}s after the previous event",
    "failed_attempts_last_5min": "followed {value:.0f} failed attempts in the last 5 minutes",
    "auth_failed": "was itself a failed authentication attempt",
    "session_duration_deviation": "had a session duration far from this user's norm",
    "baseline_confidence": "came from a user we have very little history on (cold start)",
    "is_privilege_escalation_action": "was a privilege-escalation action",
}


def _phrase(feature: str, value: float) -> str:
    template = FEATURE_PHRASES.get(feature)
    if template is None:
        return f"had an unusual value for '{feature}' ({value:.2f})"
    try:
        return template.format(value=value)
    except (KeyError, ValueError):
        return template


def _sentence_from_top(top: list[tuple[str, float, float]]) -> str:
    """top: list of (feature_name, feature_value, contribution) sorted
    by |contribution| descending."""
    if not top:
        return "No single feature stood out; risk score was driven by a broad combination of small deviations."
    phrases = [_phrase(f, v) for f, v, _ in top[:3]]
    if len(phrases) == 1:
        return f"Flagged because this event {phrases[0]}."
    if len(phrases) == 2:
        return f"Flagged because this event {phrases[0]}, and {phrases[1]}."
    return f"Flagged because this event {phrases[0]}, {phrases[1]}, and {phrases[2]}."


def build_shap_explainer(model):
    """Build a SHAP TreeExplainer ONCE for a fitted classifier model.
    Rebuilding this per-event (the old behavior) walks the entire tree
    ensemble every single call, which is why pre-scoring hundreds of
    live events at startup could take minutes and never finish. Build
    it once right after training and reuse it for every event."""
    import shap
    return shap.TreeExplainer(model)


def explain_classifier(model, feature_row: dict, feature_names: list[str], top_k: int = 3,
                        explainer=None) -> dict:
    """SHAP explanation for one row scored by the (already fit) attack
    classifier's underlying tree model. `model` should be the fitted
    LightGBM/GradientBoosting estimator (e.g. clf.model).

    Pass a pre-built `explainer` (from build_shap_explainer) to avoid
    rebuilding a TreeExplainer on every call — that rebuild is the
    expensive part, not the actual value computation."""
    if explainer is None:
        explainer = build_shap_explainer(model)

    X = pd.DataFrame([feature_row])[feature_names].values.astype(float)
    shap_values = explainer.shap_values(X)

    # Multi-class LightGBM returns a list of arrays (one per class) or a
    # 3D array depending on version; reduce to the predicted class' row.
    if isinstance(shap_values, list):
        pred_class_idx = int(np.argmax(model.predict_proba(X)[0]))
        row = shap_values[pred_class_idx][0]
    elif shap_values.ndim == 3:
        pred_class_idx = int(np.argmax(model.predict_proba(X)[0]))
        row = shap_values[0, :, pred_class_idx]
    else:
        row = shap_values[0]

    contributions = list(zip(feature_names, X[0], row))
    contributions.sort(key=lambda t: abs(t[2]), reverse=True)
    top = contributions[:top_k]

    return {
        "top_features": [
            {"feature": f, "value": float(v), "contribution": float(c)} for f, v, c in top
        ],
        "sentence": _sentence_from_top(top),
    }


def explain_anomaly(feature_row: dict, feature_means: dict, feature_stds: dict, top_k: int = 3) -> dict:
    """Fallback explanation with no classifier/label: rank features by
    how many standard deviations they sit from the *population* mean
    (computed once over training data and passed in). Good enough to
    explain genuinely novel anomalies the classifier has no class for."""
    scored = []
    for feat, val in feature_row.items():
        mean = feature_means.get(feat, 0.0)
        std = feature_stds.get(feat, 0.0) or 1e-6
        z = (val - mean) / std
        scored.append((feat, val, z))
    scored.sort(key=lambda t: abs(t[2]), reverse=True)
    top = scored[:top_k]
    return {
        "top_features": [
            {"feature": f, "value": float(v), "contribution": float(z)} for f, v, z in top
        ],
        "sentence": _sentence_from_top(top),
    }


def fit_population_stats(feature_rows: list[dict], feature_names: list[str]):
    """Precompute mean/std per feature over a training set, for use by
    explain_anomaly()."""
    df = pd.DataFrame(feature_rows)[feature_names]
    return df.mean().to_dict(), df.std().replace(0, 1e-6).to_dict()
# done