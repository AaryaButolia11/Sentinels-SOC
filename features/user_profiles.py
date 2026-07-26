"""
user_profiles.py
================

Maintains a rolling behavioral baseline per user (and per device) built
incrementally from a stream of AccessEvents. This is the "what does
normal look like for this specific person" store that feature_engineering.py
compares each new event against.

Design notes
------------
- Everything is updated online (one event at a time) so this works both
  for offline batch feature building AND for a live streaming pipeline.
- We keep small, cheap-to-update running stats rather than storing full
  event history: counts, running mean/variance (Welford), sets of seen
  values (devices, countries, resources), and an hour-of-day histogram.
- `UserProfile.n_events` is what `cold_start.py` uses to decide how much
  to trust this profile vs. the population prior.
"""

from __future__ import annotations
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from math import radians, sin, cos, sqrt, atan2
from typing import Optional


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    p1, p2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(p1) * cos(p2) * sin(dlambda / 2) ** 2
    return 2 * R * atan2(sqrt(a), sqrt(1 - a))


@dataclass
class RunningStat:
    """Welford's online mean/variance so we never need the full history."""
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return sqrt(self.m2 / (self.n - 1))


@dataclass
class UserProfile:
    user_id: str
    n_events: int = 0
    devices: set = field(default_factory=set)
    countries: set = field(default_factory=set)
    resources: Counter = field(default_factory=Counter)
    hour_histogram: Counter = field(default_factory=Counter)
    session_duration: RunningStat = field(default_factory=RunningStat)
    last_event_ts: Optional[object] = None
    last_lat: Optional[float] = None
    last_lon: Optional[float] = None
    # home location = running average of lat/lon (cheap centroid; good
    # enough since most users cluster tightly around one office/home)
    home_lat_stat: RunningStat = field(default_factory=RunningStat)
    home_lon_stat: RunningStat = field(default_factory=RunningStat)
    failed_auth_count: int = 0

    # ---- derived / read helpers -------------------------------------------------
    @property
    def home_lat(self) -> float:
        return self.home_lat_stat.mean

    @property
    def home_lon(self) -> float:
        return self.home_lon_stat.mean

    def typical_hours(self, top_k: int = 6) -> set:
        return {h for h, _ in self.hour_histogram.most_common(top_k)}

    def resource_familiarity(self, resource: str) -> float:
        """Fraction of this user's historical events that touched `resource`."""
        if self.n_events == 0:
            return 0.0
        return self.resources.get(resource, 0) / self.n_events

    def hour_familiarity(self, hour: int) -> float:
        if self.n_events == 0:
            return 0.0
        return self.hour_histogram.get(hour, 0) / self.n_events

    # ---- update -------------------------------------------------------------
    def update(self, event: dict):
        """Update the baseline with a new (already-seen / labeled-normal)
        event. Call this AFTER scoring, so the baseline reflects history
        strictly prior to the event being judged -- this avoids leaking
        the current event into its own baseline comparison."""
        self.n_events += 1
        self.devices.add(event["device_id"])
        self.countries.add(event["geo_country"])
        self.resources[event["resource"]] += 1
        self.hour_histogram[event["timestamp"].hour] += 1
        if event.get("session_duration_s") is not None:
            self.session_duration.update(float(event["session_duration_s"]))
        self.home_lat_stat.update(event["geo_lat"])
        self.home_lon_stat.update(event["geo_lon"])
        if event.get("auth_result") == "failure":
            self.failed_auth_count += 1
        self.last_event_ts = event["timestamp"]
        self.last_lat = event["geo_lat"]
        self.last_lon = event["geo_lon"]


class ProfileStore:
    """In-memory registry of UserProfiles, keyed by user_id.

    In production this would be backed by Redis/a key-value store so a
    streaming worker can look up + update baselines with low latency.
    Also tracks a rolling window of recent (per-user) auth failures for
    brute-force-style features (failed_attempts_last_5min).
    """

    def __init__(self, recent_window_events: int = 50):
        self.profiles: dict[str, UserProfile] = {}
        self.recent_events: dict[str, list] = defaultdict(list)
        self.recent_window_events = recent_window_events

    def get(self, user_id: str) -> UserProfile:
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(user_id=user_id)
        return self.profiles[user_id]

    def recent_failed_attempts(self, user_id: str, now, window_seconds: int = 300) -> int:
        events = self.recent_events.get(user_id, [])
        count = 0
        for ts, result in events:
            if (now - ts).total_seconds() <= window_seconds and result == "failure":
                count += 1
        return count

    def seconds_since_last_event(self, user_id: str, now) -> Optional[float]:
        profile = self.profiles.get(user_id)
        if profile is None or profile.last_event_ts is None:
            return None
        return (now - profile.last_event_ts).total_seconds()

    def geo_velocity_kmh(self, user_id: str, now, lat, lon) -> Optional[float]:
        """Implied travel speed (km/h) between this event and the user's
        last known location. This is the core "impossible travel" signal."""
        profile = self.profiles.get(user_id)
        if profile is None or profile.last_event_ts is None or profile.last_lat is None:
            return None
        seconds = (now - profile.last_event_ts).total_seconds()
        if seconds <= 0:
            return None
        dist_km = haversine_km(profile.last_lat, profile.last_lon, lat, lon)
        hours = seconds / 3600.0
        return dist_km / hours if hours > 0 else float("inf")

    def record_event(self, user_id: str, ts, auth_result: str):
        """Track raw (timestamp, result) pairs for short-window features
        (e.g. failed logins in the last 5 minutes), independent of the
        aggregate UserProfile stats."""
        lst = self.recent_events[user_id]
        lst.append((ts, auth_result))
        if len(lst) > self.recent_window_events:
            del lst[0: len(lst) - self.recent_window_events]

    def update(self, event: dict):
        profile = self.get(event["user_id"])
        profile.update(event)
        self.record_event(event["user_id"], event["timestamp"], event.get("auth_result", "success"))


def population_baseline(profiles: dict[str, UserProfile]) -> dict:
    """Aggregate stats across ALL users -> used as the prior for brand-new
    users with little/no history (see cold_start.py)."""
    all_hours = Counter()
    all_resources = Counter()
    session_means = []
    n_events_total = 0
    for p in profiles.values():
        all_hours.update(p.hour_histogram)
        all_resources.update(p.resources)
        if p.session_duration.n > 0:
            session_means.append(p.session_duration.mean)
        n_events_total += p.n_events

    return {
        "hour_histogram": all_hours,
        "resource_histogram": all_resources,
        "avg_session_duration": sum(session_means) / len(session_means) if session_means else 300.0,
        "n_events_total": n_events_total,
    }