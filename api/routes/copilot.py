"""
routes/copilot.py
=================
AI Security Copilot.

Turns a raw alert (risk score + attack label + SHAP explanation) into an
analyst-ready briefing: a plain-English situation summary, a severity
call, a MITRE ATT&CK mapping, and a *prioritized, specific* response
playbook the analyst can act on immediately.

Two generation paths, same output shape:

  1. LLM path (preferred, industry-realistic): if ``GROQ_API_KEY`` is
     set, we call Groq's free OpenAI-compatible Chat Completions API
     (``llama-3.3-70b-versatile`` by default) with a tightly-scoped
     defensive-SOC prompt built from the alert's own evidence. The model
     never sees anything but the structured alert, so it can only reason
     about *this* event. Groq's free tier needs no credit card, which is
     why it's the default provider here.

  2. Deterministic path (always available, zero external calls): a
     per-attack-type playbook grounded in the alert's specific fields.
     This is what runs in an air-gapped demo, in CI, or whenever the key
     is absent -- so the Copilot is never a blank box.

The endpoint degrades gracefully: any failure in the LLM path (missing
key, network error, timeout, bad response) falls back to the
deterministic playbook and flags ``"source": "playbook"`` so the UI can
be honest about where the words came from.

Environment variables:
  GROQ_API_KEY      -- enables the LLM path (get one free at console.groq.com)
  SOC_COPILOT_MODEL -- override the Groq model (default llama-3.3-70b-versatile)
  GROQ_BASE_URL     -- override the API base (default https://api.groq.com/openai/v1)
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.init_db import get_db
from ..db.models import AlertDB, EventDB

router = APIRouter(prefix="/copilot", tags=["copilot"])


# ---------------------------------------------------------------------------
# Per-attack-type defensive knowledge base. This is deliberately concrete:
# a real SOC playbook names the containment step, not "investigate further".
# MITRE technique IDs are included because analysts triage by them.
# ---------------------------------------------------------------------------
PLAYBOOK = {
    "brute_force": {
        "mitre": "T1110 (Brute Force)",
        "severity": "High",
        "one_liner": "Repeated failed authentications from an unfamiliar origin, consistent with credential guessing or password spraying.",
        "actions": [
            "Lock or force-rotate the targeted account's credentials immediately.",
            "Rate-limit or temporarily block the source IP / ASN at the edge.",
            "Confirm whether any attempt in the burst succeeded; if so, treat the account as compromised and revoke active sessions.",
            "Enable or verify MFA on the account before re-enabling it.",
        ],
        "hunt": "Pivot on the source IP across all users -- brute force is rarely aimed at a single account.",
    },
    "credential_misuse": {
        "mitre": "T1078 (Valid Accounts)",
        "severity": "High",
        "one_liner": "Valid credentials used to reach a high-sensitivity resource the account has no history of touching, often off-hours.",
        "actions": [
            "Contact the account owner out-of-band to confirm the access was intentional.",
            "Review what was read/exfiltrated from the sensitive resource during the session.",
            "Suspend the session and require re-authentication with MFA.",
            "Check for privilege changes made in the same window.",
        ],
        "hunt": "Compare this access against the user's 30-day resource baseline; look for a preceding phishing or token-theft event.",
    },
    "lateral_movement": {
        "mitre": "T1021 (Remote Services) / T1570 (Lateral Tool Transfer)",
        "severity": "Critical",
        "one_liner": "Rapid hops across escalating-sensitivity resources from one foothold, the classic post-compromise pivot pattern.",
        "actions": [
            "Isolate the originating host/device from the network now -- containment beats investigation here.",
            "Revoke the account's tokens and kill active sessions across all systems.",
            "Snapshot the host for forensics before remediation destroys evidence.",
            "Audit every resource touched in the hop chain for planted persistence.",
        ],
        "hunt": "Reconstruct the full kill chain: what was the initial foothold, and which credentials were reused between hops?",
    },
    "impossible_travel": {
        "mitre": "T1078 (Valid Accounts) / geovelocity anomaly",
        "severity": "High",
        "one_liner": "The same account authenticated from two locations too far apart to be physically possible in the elapsed time.",
        "actions": [
            "Treat the second (anomalous) session as hostile and terminate it.",
            "Force a global credential reset and MFA re-enrollment for the account.",
            "Confirm the user's true location out-of-band; rule out VPN/proxy false positives before escalating.",
            "Review actions taken during the anomalous session for data access or config changes.",
        ],
        "hunt": "Check whether the far-side IP appears for other accounts -- shared malicious infrastructure is common.",
    },
    "device_spoofing": {
        "mitre": "T1036 (Masquerading) / T1550 (Use of Alternate Auth Material)",
        "severity": "High",
        "one_liner": "A trusted device identifier appears with a fingerprint (geo/IP/hour) inconsistent with how that device has ever behaved.",
        "actions": [
            "De-trust the device identifier and require full re-enrollment.",
            "Invalidate any device-bound tokens or certificates tied to that ID.",
            "Verify with the owner whether the real device was lost, stolen, or cloned.",
            "Tighten device-attestation / conditional-access policy for the affected resource.",
        ],
        "hunt": "Look for the genuine device active elsewhere at the same time -- concurrent use confirms the spoof.",
    },
    "unknown": {
        "mitre": "Unclassified anomaly",
        "severity": "Medium",
        "one_liner": "The unsupervised model flagged this event as behaviorally abnormal, but it doesn't match a known attack signature.",
        "actions": [
            "Manually review the top contributing features listed in the alert.",
            "Compare the event against the user's established baseline.",
            "Decide whether this represents a novel technique worth labeling for retraining.",
        ],
        "hunt": "Novel anomalies are where new detections come from -- capture the pattern if it recurs.",
    },
}


class CopilotRequest(BaseModel):
    alert_id: Optional[str] = None
    # Allow an inline alert too, so the panel can query without a DB round-trip.
    predicted_label: Optional[str] = None
    risk_score: Optional[float] = None
    explanation: Optional[str] = None
    user_id: Optional[str] = None
    question: Optional[str] = None  # optional free-form analyst question


def _severity_from_score(score: float, base: str) -> str:
    """Nudge the playbook's default severity by the actual risk score so
    a 0.98 lateral-movement reads hotter than a borderline 0.61 one."""
    if score is None:
        return base
    if score >= 0.85:
        return "Critical" if base in ("Critical", "High") else "High"
    if score >= 0.7:
        return base
    return "Medium" if base != "Critical" else "High"


def _deterministic_brief(ctx: dict) -> dict:
    label = ctx.get("predicted_label") or "unknown"
    pb = PLAYBOOK.get(label, PLAYBOOK["unknown"])
    score = ctx.get("risk_score")
    risk_100 = int(round((score or 0) * 100))
    severity = _severity_from_score(score, pb["severity"])

    who = ctx.get("user_id") or "the account"
    evidence = ctx.get("explanation") or "multiple small behavioral deviations combined to raise the score"

    summary = (
        f"{who} triggered a {label.replace('_', ' ')} alert at risk {risk_100}/100. "
        f"{pb['one_liner']} Detection evidence: {evidence}"
    )

    return {
        "source": "playbook",
        "headline": f"{label.replace('_', ' ').title()} — {severity} severity",
        "summary": summary,
        "mitre": pb["mitre"],
        "severity": severity,
        "risk_score": risk_100,
        "recommended_actions": pb["actions"],
        "threat_hunt": pb["hunt"],
    }


SYSTEM_PROMPT = (
    "You are a Tier-2 SOC analyst copilot for a defensive behavioral "
    "anomaly detection system. You only ever advise on defense, "
    "containment, and investigation -- never on attacking. Write a "
    "concise analyst briefing with: (1) a two-sentence situation summary, "
    "(2) the MITRE ATT&CK technique, (3) a numbered list of prioritized "
    "containment/response actions specific to the evidence, and (4) one "
    "threat-hunting pivot. Keep it under 180 words."
)


def _build_user_prompt(ctx: dict, question: Optional[str]) -> str:
    label = ctx.get("predicted_label") or "unknown anomaly"
    risk_100 = int(round((ctx.get("risk_score") or 0) * 100))
    lines = [
        "An alert was raised. Here is the structured evidence:",
        f"- Predicted attack type: {label}",
        f"- Risk score: {risk_100}/100",
        f"- Affected account: {ctx.get('user_id', 'unknown')}",
        f"- Resource: {ctx.get('resource', 'unknown')}",
        f"- Action: {ctx.get('action', 'unknown')}",
        f"- Origin country: {ctx.get('geo_country', 'unknown')}",
        f"- Model explanation: {ctx.get('explanation', 'n/a')}",
    ]
    if question:
        lines += ["", f"The analyst also asks: {question}"]
    return "\n".join(lines)


def _llm_brief(ctx: dict, question: Optional[str]) -> Optional[dict]:
    """Call Groq's free OpenAI-compatible API if a key is configured.
    Returns None on any failure so the caller can fall back to the
    deterministic playbook."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        import httpx

        base_url = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
        resp = httpx.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": os.environ.get("SOC_COPILOT_MODEL", "llama-3.3-70b-versatile"),
                "max_tokens": 600,
                "temperature": 0.3,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(ctx, question)},
                ],
            },
            timeout=20.0,
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices") or []
        text = (
            (choices[0].get("message", {}).get("content", "") if choices else "")
        ).strip()
        if not text:
            return None

        label = ctx.get("predicted_label") or "unknown"
        pb = PLAYBOOK.get(label, PLAYBOOK["unknown"])
        return {
            "source": "llm",
            "headline": f"{label.replace('_', ' ').title()} — {_severity_from_score(ctx.get('risk_score'), pb['severity'])} severity",
            "summary": text,
            "mitre": pb["mitre"],
            "severity": _severity_from_score(ctx.get("risk_score"), pb["severity"]),
            "risk_score": int(round((ctx.get("risk_score") or 0) * 100)),
            "recommended_actions": pb["actions"],
            "threat_hunt": pb["hunt"],
        }
    except Exception:
        return None


@router.post("")
def copilot_brief(payload: CopilotRequest, db: Session = Depends(get_db)):
    """Generate an analyst briefing for an alert. Prefers the LLM path,
    always falls back to the deterministic playbook."""
    ctx: dict = {}

    if payload.alert_id:
        alert = db.query(AlertDB).filter(AlertDB.alert_id == payload.alert_id).first()
        if not alert:
            raise HTTPException(404, "alert not found")
        ctx.update(
            predicted_label=alert.predicted_label,
            risk_score=alert.risk_score,
            explanation=alert.explanation_sentence,
            user_id=alert.user_id,
        )
        ev = db.query(EventDB).filter(EventDB.event_id == alert.event_id).first()
        if ev:
            ctx.update(
                resource=ev.resource,
                action=ev.action,
                geo_country=(ev.raw or {}).get("geo_country"),
            )
    else:
        # inline path
        ctx.update(
            predicted_label=payload.predicted_label,
            risk_score=payload.risk_score,
            explanation=payload.explanation,
            user_id=payload.user_id,
        )

    if not ctx.get("predicted_label") and payload.risk_score is None:
        raise HTTPException(400, "provide an alert_id or inline alert fields")

    brief = _llm_brief(ctx, payload.question) or _deterministic_brief(ctx)
    return brief


@router.get("/health")
def copilot_health():
    """Lets the UI show whether live LLM briefings are available or if it
    will use the offline playbook."""
    return {
        "llm_available": bool(os.environ.get("GROQ_API_KEY")),
        "provider": "groq",
        "model": os.environ.get("SOC_COPILOT_MODEL", "llama-3.3-70b-versatile"),
    }