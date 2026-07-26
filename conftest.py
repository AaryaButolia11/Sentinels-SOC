"""
Shared pytest fixtures. The project modules use `sys.path.insert` tricks
(e.g. feature_engineering.py imports `from user_profiles import ...`
with no package prefix), so tests need the same sibling folders on
sys.path before importing anything from the project.
"""
from __future__ import annotations
import os
import sys
import csv
from datetime import datetime
import pytest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
for sub in ("data", "features", "models", "streaming", "api"):
    sys.path.insert(0, os.path.join(ROOT, sub))

SAMPLE_LOGS_PATH = os.path.join(ROOT, "data", "sample_logs.csv")


def load_events(path=SAMPLE_LOGS_PATH):
    events = []
    with open(path) as f:
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


@pytest.fixture(scope="session")
def sample_events():
    if not os.path.exists(SAMPLE_LOGS_PATH):
        pytest.skip(
            "sample_logs.csv not found -- run "
            "`python data/generate_logs.py --out data/sample_logs.csv` first"
        )
    return load_events()


@pytest.fixture(scope="session")
def feature_table(sample_events):
    from feature_engineering import build_feature_table
    return build_feature_table(sample_events) 