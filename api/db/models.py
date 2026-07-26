"""
db/models.py
============
SQLAlchemy models: Event (raw log), Alert (flagged event + score +
explanation), Feedback (analyst verdict on an alert).
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class EventDB(Base):
    __tablename__ = "events"
    event_id = Column(String, primary_key=True)
    user_id = Column(String, index=True)
    device_id = Column(String)
    timestamp = Column(DateTime, index=True)
    resource = Column(String)
    action = Column(String)
    raw = Column(JSON)  # full original event dict


class AlertDB(Base):
    __tablename__ = "alerts"
    alert_id = Column(String, primary_key=True)
    event_id = Column(String, ForeignKey("events.event_id"))
    user_id = Column(String, index=True)
    risk_score = Column(Float)
    predicted_label = Column(String)
    label_confidence = Column(Float)
    explanation_sentence = Column(String)
    explanation_top_features = Column(JSON)
    # --- enrichment: severity, MITRE ATT&CK, recommended response ---
    severity = Column(String, index=True)          # Critical | High | Medium | Low
    severity_score = Column(Float)
    mitre_technique_id = Column(String)            # e.g. "T1110"
    mitre_technique = Column(String)               # e.g. "Brute Force"
    mitre_tactic = Column(String)                  # e.g. "Credential Access"
    recommended_actions = Column(JSON)             # ["Block source IP", ...]
    created_at = Column(DateTime, default=datetime.utcnow)

    feedback = relationship("FeedbackDB", back_populates="alert", uselist=False)


class FeedbackDB(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"))
    verdict = Column(String)  # "confirmed" | "false_positive"
    analyst = Column(String, default="demo_analyst")
    created_at = Column(DateTime, default=datetime.utcnow)

    alert = relationship("AlertDB", back_populates="feedback")