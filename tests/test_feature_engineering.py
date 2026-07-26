from __future__ import annotations
from feature_engineering import FEATURE_NAMES, compute_features, build_feature_table
from user_profiles import ProfileStore, population_baseline
from cold_start import ColdStartBlender


def test_build_feature_table_shapes(feature_table, sample_events):
    feature_rows, labels, store = feature_table
    assert len(feature_rows) == len(sample_events)
    assert len(labels) == len(sample_events)
    # every row has exactly the declared feature columns, nothing missing
    for row in feature_rows[:50]:
        assert set(row.keys()) == set(FEATURE_NAMES)


def test_labels_include_attack_types(feature_table):
    _, labels, _ = feature_table
    label_set = set(labels)
    assert "none" in label_set
    # at least one real attack type should show up in a 14-day synthetic run
    assert label_set - {"none"}


def test_event_never_leaks_into_its_own_baseline(sample_events):
    """The ordering rule in feature_engineering.py: features must be
    computed BEFORE store.update() for the same event, or an event's
    own device/resource would count as 'already seen'."""
    store = ProfileStore()
    blender = ColdStartBlender()
    population = population_baseline(store.profiles)

    first_event = sample_events[0]
    feats = compute_features(first_event, store, population, blender)

    # brand-new user, first ever event -> must look like a cold start,
    # not like a device/resource the profile has already seen
    assert feats["is_new_device"] == 1
    assert feats["baseline_confidence"] == 0.0


def test_feature_values_are_finite(feature_table):
    import math
    feature_rows, _, _ = feature_table
    for row in feature_rows[:200]:
        for k, v in row.items():
            assert not (isinstance(v, float) and math.isnan(v)), f"{k} is NaN"