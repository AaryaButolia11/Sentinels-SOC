"""
routes/alerts.py
================
GET /alerts            - list recent alerts (optionally filter by user_id)
GET /alerts/{alert_id} - full detail incl. explanation + linked event
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..db.init_db import get_db
from ..db.models import AlertDB, EventDB

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _alert_to_dict(a: AlertDB) -> dict:
    return {
        "alert_id": a.alert_id,
        "event_id": a.event_id,
        "user_id": a.user_id,
        "risk_score": a.risk_score,
        "predicted_label": a.predicted_label,
        "label_confidence": a.label_confidence,
        "explanation": a.explanation_sentence,
        "top_features": a.explanation_top_features,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "verdict": a.feedback.verdict if a.feedback else None,
    }


@router.get("")
def list_alerts(user_id: Optional[str] = Query(None), limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(AlertDB).order_by(AlertDB.created_at.desc())
    if user_id:
        q = q.filter(AlertDB.user_id == user_id)
    alerts = q.limit(limit).all()
    return [_alert_to_dict(a) for a in alerts]


@router.get("/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    a = db.query(AlertDB).filter(AlertDB.alert_id == alert_id).first()
    if not a:
        raise HTTPException(404, "alert not found")
    ev = db.query(EventDB).filter(EventDB.event_id == a.event_id).first()
    d = _alert_to_dict(a)
    d["event"] = ev.raw if ev else None
    return d