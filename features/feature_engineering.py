"""
feature_engineering.py
======================

Turns a raw AccessEvent (as a dict) + the user's rolling baseline into a
fixed-length numeric feature vector suitable for both the unsupervised
anomaly model and the supervised attack classifier.

IMPORTANT ordering rule: for every event we must compute features
BEFORE calling `ProfileStore.update(event)` for that same event, or the
event will "see itself" in its own baseline and anomalies will be
smoothed away. `build_feature_table()` below enforces that ordering.
"""

from __future__ import annotations
from dataclasses import dataclass, fields
import math

from features.user_profiles import ProfileStore, population_baseline, haversine_km
from features.cold_start import ColdStartBlender


FEATURE_NAMES = [
    "hour_of_day",
    "hour_typicality",              # cold-start-blended probability of this hour for this user
    "is_new_device",
    "is_new_country",
    "device_familiarity",           # fraction of user's devices this device represents (1/n_devices) if known, else 0
    "resource_sensitivity",
    "resource_familiarity",         # cold-start-blended probability user touches this resource
    "geo_distance_from_home_km",
    "geo_velocity_kmh",             # implied travel speed since user's last event; -1 if unknown
    "seconds_since_last_event",
    "failed_attempts_last_5min",
    "auth_failed",
    "session_duration_s",
    "session_duration_deviation",   # (actual - expected) / (expected + eps), cold-start blended expectation
    "baseline_confidence",          # 0-1, how much history we have on this user (cold-start signal itself)
    "is_privilege_escalation_action",
]


def _safe_float(v, default=0.0):
    try:
        if v is None or (isinstance(v, float) and math.isnan(v)):
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def compute_features(event: dict, store: ProfileStore, population: dict,
                      blender: ColdStartBlender) -> dict:
    """Compute the feature dict for a single event. Must be called BEFORE
    store.update(event) for this same event."""
    profile = store.get(event["user_id"])
    now = event["timestamp"]
    hour = now.hour

    is_new_device = event["device_id"] not in profile.devices
    is_new_country = event["geo_country"] not in profile.countries

    device_familiarity = 0.0 if is_new_device else (
        1.0 / len(profile.devices) if profile.devices else 0.0
    )

    if blender.is_confident_home_location(profile):
        geo_distance_from_home = haversine_km(
            profile.home_lat, profile.home_lon, event["geo_lat"], event["geo_lon"]
        )
    else:
        # thin history -> fall back to 0 (can't yet claim a deviation)
        geo_distance_from_home = 0.0

    geo_velocity = store.geo_velocity_kmh(event["user_id"], now, event["geo_lat"], event["geo_lon"])
    seconds_since_last = store.seconds_since_last_event(event["user_id"], now)
    failed_recent = store.recent_failed_attempts(event["user_id"], now)

    expected_duration = blender.expected_session_duration(profile, population)
    actual_duration = _safe_float(event.get("session_duration_s"), default=expected_duration)
    duration_deviation = (actual_duration - expected_duration) / (expected_duration + 1e-6)

    feats = {
        "hour_of_day": hour,
        "hour_typicality": blender.hour_probability(profile, hour, population),
        "is_new_device": int(is_new_device),
        "is_new_country": int(is_new_country),
        "device_familiarity": device_familiarity,
        "resource_sensitivity": _safe_float(event.get("resource_sensitivity")),
        "resource_familiarity": blender.resource_probability(profile, event["resource"], population),
        "geo_distance_from_home_km": geo_distance_from_home,
        "geo_velocity_kmh": geo_velocity if geo_velocity is not None else -1.0,
        "seconds_since_last_event": seconds_since_last if seconds_since_last is not None else -1.0,
        "failed_attempts_last_5min": failed_recent,
        "auth_failed": int(event.get("auth_result") == "failure"),
        "session_duration_s": actual_duration,
        "session_duration_deviation": duration_deviation,
        "baseline_confidence": blender.confidence(profile, k=6.0),
        "is_privilege_escalation_action": int(event.get("action") == "privilege_escalation"),
    }
    return feats


def build_feature_table(events: list[dict], store: ProfileStore | None = None,
                         blender: ColdStartBlender | None = None):
    """Stream events in time order, computing features for each BEFORE
    folding it into the baseline. Returns (feature_dicts, labels, store).

    Passing in an existing `store` lets you continue building baselines
    across multiple calls (e.g. batch-train then keep scoring live).
    """
    store = store or ProfileStore()
    blender = blender or ColdStartBlender()

    feature_rows = []
    labels = []

    for i, event in enumerate(events):
        # Recompute a population snapshot periodically (cheap for demo
        # sizes; in production you'd refresh this on a schedule instead
        # of every event).
        if i % 500 == 0:
            population = population_baseline(store.profiles)

        feats = compute_features(event, store, population, blender)
        feature_rows.append(feats)
        labels.append(event.get("label", "none"))

        store.update(event)

    return feature_rows, labels, store


if __name__ == "__main__":
    # Quick smoke test using the generated sample_logs.csv
    import csv
    import sys
    from datetime import datetime

    sys.path.insert(0, "../data")
    path = "../data/sample_logs.csv"
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
            row["is_new_device"] = row["is_new_device"] == "True"
            events.append(row)

    feature_rows, labels, store = build_feature_table(events)
    print(f"Built {len(feature_rows)} feature rows from {len(events)} events")
    print("Sample feature row:", feature_rows[100])
    print("Sample label:", labels[100])
    print(f"Profiles tracked: {len(store.profiles)}")