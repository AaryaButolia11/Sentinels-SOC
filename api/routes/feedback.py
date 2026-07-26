"""
routes/feedback.py
===================
POST /feedback  { "alert_id": "...", "verdict": "confirmed" | "false_positive" }

This is the "secret weapon" from the build guide: every verdict is
stored AND fed into the in-memory DriftMonitor. If drift is detected,
`should_retrain` flips to true in the response so the dashboard can
show a "retraining recommended" banner immediately, without waiting
for a scheduled batch job.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.init_db import get_db
from ..db.models import AlertDB, FeedbackDB

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "models"))
from models.drift_monitor import DriftMonitor, FeedbackEvent

router = APIRouter(prefix="/feedback", tags=["feedback"])

# Single shared monitor instance for this demo process. In production
# this state would live in Redis/DB, keyed per model version.
drift_monitor = DriftMonitor(window_size=200, fp_rate_threshold=0.30, min_feedback_for_check=20)


# ---------------------------------------------------------------------------
# Demo seed
# ---------------------------------------------------------------------------
# The drift panel stays blank ("not enough feedback yet") until an analyst has
# triaged >= min_feedback_for_check alerts. For a live demo that's awkward — you
# don't want to hand-click 20 alerts on stage. So we pre-load a realistic batch
# of triage verdicts here, purely so the Model Health & Drift panel renders with
# live bars from the first second. Real analyst feedback (POST /feedback) simply
# stacks on top of this. Set SEED_DEMO_FEEDBACK = False to disable.
SEED_DEMO_FEEDBACK = True

# A healthy history: mostly confirmed, a few false positives spread out -> the
# panel reads "stable" (rolling FP ~12%, well under the 30% threshold).
# To instead demo drift DETECTION (the "retrain recommended" banner + red
# reason line), swap _SEED_FALSE_POSITIVE_IDX to something like
# {12,13,14,16,18,19,20,21,22,23} — a cluster of false positives in the recent
# half pushes the new-window FP rate up and trips the jump threshold.
_SEED_LABELS = ["brute_force", "credential_misuse", "lateral_movement",
                "impossible_travel", "device_spoofing"]
_SEED_FALSE_POSITIVE_IDX = {3, 14, 21}
_SEED_COUNT = 24


def _seed_demo_feedback() -> None:
    t0 = datetime.utcnow() - timedelta(minutes=_SEED_COUNT)
    for i in range(_SEED_COUNT):
        verdict = "false_positive" if i in _SEED_FALSE_POSITIVE_IDX else "confirmed"
        drift_monitor.record(FeedbackEvent(
            alert_id=f"seed-{i}",
            predicted_label=_SEED_LABELS[i % len(_SEED_LABELS)],
            analyst_verdict=verdict,
            timestamp=t0 + timedelta(minutes=i),
        ))


if SEED_DEMO_FEEDBACK:
    _seed_demo_feedback()


class FeedbackIn(BaseModel):
    alert_id: str
    verdict: str  # "confirmed" | "false_positive"
    analyst: str = "demo_analyst"


@router.post("")
def submit_feedback(payload: FeedbackIn, db: Session = Depends(get_db)):
    if payload.verdict not in ("confirmed", "false_positive"):
        raise HTTPException(400, "verdict must be 'confirmed' or 'false_positive'")

    alert = db.query(AlertDB).filter(AlertDB.alert_id == payload.alert_id).first()
    if not alert:
        raise HTTPException(404, "alert not found")

    fb = FeedbackDB(alert_id=payload.alert_id, verdict=payload.verdict, analyst=payload.analyst)
    db.add(fb)
    db.commit()

    drift_monitor.record(FeedbackEvent(
        alert_id=payload.alert_id,
        predicted_label=alert.predicted_label,
        analyst_verdict=payload.verdict,
        timestamp=datetime.utcnow(),
    ))

    return {"stored": True, "drift_status": drift_monitor.status()}


@router.get("/drift-status")
def get_drift_status():
    return drift_monitor.status()