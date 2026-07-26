from __future__ import annotations
from datetime import datetime, timedelta
from drift_monitor import DriftMonitor, FeedbackEvent


def test_not_enough_feedback_yet():
    monitor = DriftMonitor(min_feedback_for_check=20)
    status = monitor.status()
    assert status["drift_detected"] is False
    assert status["should_retrain"] is False


def test_detects_drift_from_rising_fp_rate():
    monitor = DriftMonitor(window_size=100, fp_rate_threshold=0.30, min_feedback_for_check=20)
    t0 = datetime(2026, 7, 1)

    for i in range(15):
        verdict = "false_positive" if i % 8 == 0 else "confirmed"
        monitor.record(FeedbackEvent(f"a{i}", "brute_force", verdict, t0 + timedelta(minutes=i)))
    assert monitor.status()["drift_detected"] is False

    for i in range(15, 40):
        verdict = "false_positive" if i % 2 == 0 else "confirmed"
        monitor.record(FeedbackEvent(f"a{i}", "brute_force", verdict, t0 + timedelta(minutes=i)))
    status = monitor.status()
    assert status["drift_detected"] is True
    assert status["should_retrain"] is True


def test_stable_feedback_does_not_trigger_drift():
    monitor = DriftMonitor(window_size=100, fp_rate_threshold=0.30, min_feedback_for_check=20)
    t0 = datetime(2026, 7, 1)
    for i in range(50):
        monitor.record(FeedbackEvent(f"a{i}", "brute_force", "confirmed", t0 + timedelta(minutes=i)))
    status = monitor.status()
    assert status["drift_detected"] is False