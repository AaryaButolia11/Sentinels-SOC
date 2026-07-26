"""
routes/investigation.py
========================
Powers the interactive Investigation page. For a given user it assembles
everything an analyst needs on one screen:

  - the learned behavioral baseline (from the live ProfileStore): how many
    events we've seen, known devices/countries, typical active hours, home
    location, the resources they normally touch, and how confident we are
    in that baseline (the cold-start signal)
  - their alerts and recent events from the database
  - a compact risk timeline for sparkline rendering

This reads the trained pipeline via api.state (populated at startup) so it
reflects the *actual* baselines the detector is scoring against, not a
re-derived approximation.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db.init_db import get_db
from ..db.models import AlertDB, EventDB
from ..state import get_pipeline

router = APIRouter(prefix="/investigate", tags=["investigation"])


def _profile_summary(user_id: str) -> dict | None:
    pipeline = get_pipeline()
    if pipeline is None:
        return None
    profile = pipeline.store.profiles.get(user_id)
    if profile is None:
        return None

    blender = pipeline.blender
    confidence = blender.confidence(profile, k=6.0)
    top_resources = [
        {"resource": r, "count": c} for r, c in profile.resources.most_common(5)
    ]
    return {
        "user_id": user_id,
        "events_observed": profile.n_events,
        "known_devices": sorted(profile.devices),
        "known_countries": sorted(profile.countries),
        "typical_hours": sorted(profile.typical_hours(top_k=6)),
        "home_location": {
            "lat": round(profile.home_lat, 4),
            "lon": round(profile.home_lon, 4),
        },
        "top_resources": top_resources,
        "avg_session_duration_s": round(profile.session_duration.mean, 1),
        "failed_auth_count": profile.failed_auth_count,
        "baseline_confidence": round(confidence, 3),
        "is_cold_start": confidence < 0.5,
    }


@router.get("/users")
def known_users():
    """List every user the detector currently has a baseline for, with a
    quick risk indicator, so the investigation page has something to
    browse without prior knowledge of user IDs."""
    pipeline = get_pipeline()
    if pipeline is None:
        return {"ready": False, "users": []}
    users = []
    for uid, p in pipeline.store.profiles.items():
        users.append(
            {
                "user_id": uid,
                "events_observed": p.n_events,
                "failed_auth_count": p.failed_auth_count,
                "known_countries": len(p.countries),
                "known_devices": len(p.devices),
            }
        )
    users.sort(key=lambda u: u["failed_auth_count"], reverse=True)
    return {"ready": True, "users": users}


@router.get("/{user_id}")
def investigate_user(user_id: str, db: Session = Depends(get_db)):
    summary = _profile_summary(user_id)

    alerts = (
        db.query(AlertDB)
        .filter(AlertDB.user_id == user_id)
        .order_by(AlertDB.created_at.desc())
        .limit(50)
        .all()
    )
    events = (
        db.query(EventDB)
        .filter(EventDB.user_id == user_id)
        .order_by(EventDB.timestamp.desc())
        .limit(50)
        .all()
    )

    if summary is None and not alerts and not events:
        raise HTTPException(404, f"no data for user '{user_id}'")

    alert_dicts = [
        {
            "alert_id": a.alert_id,
            "risk_score": a.risk_score,
            "predicted_label": a.predicted_label,
            "label_confidence": a.label_confidence,
            "explanation": a.explanation_sentence,
            "top_features": a.explanation_top_features,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "verdict": a.feedback.verdict if a.feedback else None,
        }
        for a in alerts
    ]
    event_dicts = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "resource": e.resource,
            "action": e.action,
            "device_id": e.device_id,
            "geo_country": (e.raw or {}).get("geo_country"),
            "auth_result": (e.raw or {}).get("auth_result"),
            "risk_score": (e.raw or {}).get("_risk_score"),
        }
        for e in events
    ]

    # Risk timeline (oldest -> newest) for a sparkline.
    timeline = [
        {"t": a["created_at"], "risk": a["risk_score"], "label": a["predicted_label"]}
        for a in reversed(alert_dicts)
    ]

    return {
        "user_id": user_id,
        "profile": summary,
        "alerts": alert_dicts,
        "recent_events": event_dicts,
        "risk_timeline": timeline,
        "alert_count": len(alert_dicts),
    }
