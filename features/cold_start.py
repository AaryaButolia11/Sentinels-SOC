"""
cold_start.py
=============

Handles the "brand new user/device with little or no history" problem.

The naive approaches are both bad:
  - "no baseline yet -> skip scoring"    -> blind spot attackers can exploit
  - "no baseline yet -> flag everything" -> alert fatigue, kills trust

Instead we use Bayesian shrinkage (a k-scheme / "credibility weighting",
the same idea behind e.g. IMDB's weighted rating): blend the user's own
observed behavior with the population-level prior, with the weight given
to the user's own data increasing smoothly as they accumulate events.

    blended = (n / (n + k)) * user_estimate + (k / (n + k)) * population_estimate

  - n = number of events this user has contributed so far
  - k = "prior strength" - how many events it takes before we trust the
        user's own data roughly as much as the population prior. Higher k
        = more conservative / slower to trust a thin history.

This is applied per-feature (typical hour probability, resource
familiarity, expected session duration, etc.), not as a single global
switch, so a user with 40 events but who has literally never touched
"admin_console" still gets an appropriately low familiarity score for
that resource specifically.
"""

from __future__ import annotations
from dataclasses import dataclass

from features.user_profiles import UserProfile


@dataclass
class ColdStartBlender:
    k_hour: float = 8.0          # prior strength for "is this a typical hour" belief
    k_resource: float = 5.0      # prior strength for resource familiarity
    k_session: float = 6.0       # prior strength for expected session duration
    k_geo: float = 4.0           # prior strength for "home location" trust

    @staticmethod
    def _shrink(n: float, k: float) -> float:
        """Returns weight in [0, 1) given to the user's own estimate."""
        return n / (n + k) if (n + k) > 0 else 0.0

    def hour_probability(self, profile: UserProfile, hour: int, population: dict) -> float:
        n = profile.n_events
        user_p = profile.hour_familiarity(hour)
        pop_total = max(population.get("n_events_total", 0), 1)
        pop_p = population.get("hour_histogram", {}).get(hour, 0) / pop_total
        w = self._shrink(n, self.k_hour)
        return w * user_p + (1 - w) * pop_p

    def resource_probability(self, profile: UserProfile, resource: str, population: dict) -> float:
        n = profile.n_events
        user_p = profile.resource_familiarity(resource)
        pop_total = max(population.get("n_events_total", 0), 1)
        pop_p = population.get("resource_histogram", {}).get(resource, 0) / pop_total
        w = self._shrink(n, self.k_resource)
        return w * user_p + (1 - w) * pop_p

    def expected_session_duration(self, profile: UserProfile, population: dict) -> float:
        n = profile.session_duration.n
        user_mean = profile.session_duration.mean if n > 0 else population.get("avg_session_duration", 300.0)
        pop_mean = population.get("avg_session_duration", 300.0)
        w = self._shrink(n, self.k_session)
        return w * user_mean + (1 - w) * pop_mean

    def is_confident_home_location(self, profile: UserProfile) -> bool:
        """Whether we trust this user's centroid enough to compute
        meaningful geo-distance-from-home / geo-velocity features."""
        return profile.home_lat_stat.n >= self.k_geo

    def confidence(self, profile: UserProfile, k: float) -> float:
        """Generic 0-1 'how much do we trust this profile' score, usable
        directly as a feature (`baseline_confidence`) so the anomaly
        model can itself learn to be more lenient on thin profiles."""
        return self._shrink(profile.n_events, k)