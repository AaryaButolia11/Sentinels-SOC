"""
drift_monitor.py
================

Watches analyst feedback over time and decides when the model has gone
stale enough to warrant retraining. Two complementary signals:

  1. Rolling disagreement rate: of the last N alerts an analyst has
     triaged, what fraction did they mark "false_positive"? If this
     rises above `fp_rate_threshold`, the model is over-flagging and
     needs recalibration (usually: raise the anomaly threshold, or
     retrain the classifier on the newly confirmed labels).

  2. ADWIN-style windowed comparison (simplified): split recent
     feedback into an "old" half and a "new" half, compare their
     false-positive rates. A big jump between halves is a much
     stronger drift signal than the rolling rate alone, because it
     catches a *sudden* change rather than a slow one.

This is intentionally simple (no external `river` dependency required)
but is structured so a real ADWIN/DDM detector could be swapped in
without changing the calling code in the API layer.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import deque


@dataclass
class FeedbackEvent:
    alert_id: str
    predicted_label: str
    analyst_verdict: str   # "confirmed" | "false_positive"
    timestamp: object


@dataclass
class DriftMonitor:
    window_size: int = 200
    fp_rate_threshold: float = 0.30      # rolling FP rate that triggers a warning
    split_jump_threshold: float = 0.15   # min jump between old/new half to flag drift
    min_feedback_for_check: int = 20

    _feedback: deque = field(default_factory=lambda: deque(maxlen=200))

    def __post_init__(self):
        self._feedback = deque(maxlen=self.window_size)

    def record(self, feedback: FeedbackEvent):
        self._feedback.append(feedback)

    def _fp_rate(self, events) -> float:
        if not events:
            return 0.0
        fp = sum(1 for e in events if e.analyst_verdict == "false_positive")
        return fp / len(events)

    def status(self) -> dict:
        events = list(self._feedback)
        n = len(events)
        if n < self.min_feedback_for_check:
            return {
                "drift_detected": False,
                "reason": f"not enough feedback yet ({n}/{self.min_feedback_for_check})",
                "rolling_fp_rate": None,
                "should_retrain": False,
            }

        rolling_fp = self._fp_rate(events)
        half = n // 2
        old_fp = self._fp_rate(events[:half])
        new_fp = self._fp_rate(events[half:])
        jump = new_fp - old_fp

        drift_by_rate = rolling_fp >= self.fp_rate_threshold
        drift_by_jump = jump >= self.split_jump_threshold

        drift_detected = drift_by_rate or drift_by_jump
        reason = []
        if drift_by_rate:
            reason.append(f"rolling FP rate {rolling_fp:.0%} >= threshold {self.fp_rate_threshold:.0%}")
        if drift_by_jump:
            reason.append(f"FP rate jumped {old_fp:.0%} -> {new_fp:.0%} (Δ{jump:.0%})")
        if not reason:
            reason.append("stable")

        return {
            "drift_detected": drift_detected,
            "reason": "; ".join(reason),
            "rolling_fp_rate": rolling_fp,
            "old_half_fp_rate": old_fp,
            "new_half_fp_rate": new_fp,
            "should_retrain": drift_detected,
            "n_feedback_in_window": n,
        }


if __name__ == "__main__":
    from datetime import datetime, timedelta

    monitor = DriftMonitor(window_size=100, min_feedback_for_check=20)
    t0 = datetime(2026, 7, 1)

    # Simulate a healthy period, then a drift onset (more false positives)
    for i in range(15):
        verdict = "false_positive" if i % 8 == 0 else "confirmed"
        monitor.record(FeedbackEvent(f"a{i}", "brute_force", verdict, t0 + timedelta(minutes=i)))
    print("After healthy period:", monitor.status())

    for i in range(15, 40):
        verdict = "false_positive" if i % 2 == 0 else "confirmed"
        monitor.record(FeedbackEvent(f"a{i}", "brute_force", verdict, t0 + timedelta(minutes=i)))
    print("\nAfter drift onset:", monitor.status())