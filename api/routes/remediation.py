"""
routes/remediation.py
======================
POST /remediation   { "alert_id": "..." }
GET  /remediation                       -> audit log of actions taken

One-click containment. Each attack type maps to the response action a SOC
analyst would actually take, and the action is written to the `remediations`
table so there's an auditable record of what was done, by whom, and against
which target (IP / device / account).

  brute_force        -> block_ip       (block the source IP)
  credential_misuse  -> block_device   (block the offending device)
  lateral_movement   -> isolate_host   (network-isolate the host)
  impossible_travel  -> lock_account   (lock the user account)
  device_spoofing    -> block_device   (block the spoofed device)

This records/simulates the action for the demo. Wiring it to a real
firewall / EDR / identity provider is a matter of calling their API at the
marked TODO — the mapping and audit trail are already here.
"""
from __future__ import annotations
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import Session

from ..db.init_db import get_db
from ..db.models import Base, AlertDB, EventDB


# attack type -> (action code, target field, button verb, done label)
REMEDIATION_MAP = {
    "brute_force":       ("block_ip",     "ip",     "Block source IP", "Source IP blocked"),
    "credential_misuse": ("block_device", "device", "Block device",    "Device blocked"),
    "lateral_movement":  ("isolate_host", "device", "Isolate host",    "Host isolated"),
    "impossible_travel": ("lock_account", "user",   "Lock account",    "Account locked"),
    "device_spoofing":   ("block_device", "device", "Block device",    "Device blocked"),
}
_DEFAULT = ("contain", "user", "Contain threat", "Threat contained")


class RemediationDB(Base):
    """Audit record of a containment action. Registered on the shared Base, so
    init_db()'s create_all() builds this table automatically at startup."""
    __tablename__ = "remediations"
    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"), index=True)
    label = Column(String)     # attack type the action responds to
    action = Column(String)    # block_ip / block_device / isolate_host / lock_account / contain
    target = Column(String)    # the IP / device / account acted upon
    analyst = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


router = APIRouter(prefix="/remediation", tags=["remediation"])


class RemediateIn(BaseModel):
    alert_id: str
    analyst: str = "demo_analyst"


def _resolve_target(field: str, alert: AlertDB, event: EventDB | None) -> str:
    raw = (event.raw if event else {}) or {}
    if field == "ip":
        return raw.get("ip_address") or "unknown-ip"
    if field == "device":
        return (event.device_id if event else None) or raw.get("device_id") or "unknown-device"
    return alert.user_id or "unknown-user"


@router.post("")
def remediate(payload: RemediateIn, db: Session = Depends(get_db)):
    alert = db.query(AlertDB).filter(AlertDB.alert_id == payload.alert_id).first()
    if not alert:
        raise HTTPException(404, "alert not found")

    # Idempotent: if this alert was already actioned, report the existing record
    # back instead of blocking the same target twice.
    existing = db.query(RemediationDB).filter(RemediationDB.alert_id == payload.alert_id).first()
    if existing:
        _, _, verb, done = REMEDIATION_MAP.get(existing.label, _DEFAULT)
        return {"ok": True, "already": True, "action": existing.action,
                "target": existing.target, "verb": verb, "done": done,
                "message": f"{done}: {existing.target}"}

    action, field, verb, done = REMEDIATION_MAP.get(alert.predicted_label, _DEFAULT)
    event = db.query(EventDB).filter(EventDB.event_id == alert.event_id).first()
    target = _resolve_target(field, alert, event)

    # TODO(real deployment): call the enforcement point here —
    #   block_ip     -> firewall / WAF API
    #   block_device -> EDR / MDM API
    #   isolate_host -> EDR network-isolation API
    #   lock_account -> identity provider (Okta / Active Directory) disable-user API

    rec = RemediationDB(
        id=str(uuid.uuid4()), alert_id=alert.alert_id, label=alert.predicted_label,
        action=action, target=target, analyst=payload.analyst,
    )
    db.add(rec)
    db.commit()
    return {"ok": True, "already": False, "action": action, "target": target,
            "verb": verb, "done": done, "message": f"{done}: {target}"}


@router.get("")
def list_remediations(db: Session = Depends(get_db)):
    rows = db.query(RemediationDB).order_by(RemediationDB.created_at.desc()).all()
    return [
        {"alert_id": r.alert_id, "label": r.label, "action": r.action,
         "target": r.target, "analyst": r.analyst,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]