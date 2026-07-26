"""
enrichment.py
=============

Turns a bare alert (risk score + predicted attack type + which resource was
touched) into the extra context a SOC analyst actually acts on:

  1. Severity      -- Critical / High / Medium / Low, blending the model's
                      anomaly risk with how sensitive the touched asset is.
                      A weird login to the coffee-menu wiki is not the same
                      incident as a weird login to the payment gateway.
  2. MITRE ATT&CK  -- maps each attack type to a real technique ID + tactic,
                      so alerts speak the language every SOC already uses.
  3. Response      -- concrete, ranked recommended actions ("Block source IP",
                      "Require MFA", "Lock account"), escalated by severity.

This is deliberately rule-based and transparent: analysts must be able to see
*why* a response was recommended, and auditors must be able to review the
mapping. It is not a black box on top of a black box.
"""

from __future__ import annotations

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

# Attack type -> MITRE ATT&CK technique. IDs/tactics chosen to match how each
# injected pattern actually behaves in generate_logs.py.
MITRE_MAP = {
    "brute_force": {
        "technique_id": "T1110", "technique": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "credential_misuse": {
        "technique_id": "T1078", "technique": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "lateral_movement": {
        "technique_id": "T1021", "technique": "Remote Services",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "impossible_travel": {
        "technique_id": "T1078", "technique": "Valid Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "device_spoofing": {
        "technique_id": "T1036", "technique": "Masquerading",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
}

# Base playbook per attack type, ordered most-decisive first.
RESPONSE_MAP = {
    "brute_force": ["Block source IP", "Temporarily lock the account", "Require MFA re-authentication"],
    "credential_misuse": ["Force password reset", "Require MFA", "Review recent privileged actions"],
    "lateral_movement": ["Isolate the affected host", "Revoke active sessions", "Escalate to incident response"],
    "impossible_travel": ["Require MFA re-authentication", "Suspend the active session", "Verify with the user out-of-band"],
    "device_spoofing": ["Block the device", "Require MFA", "Re-enroll the device fingerprint"],
}

# High-impact techniques that get a severity bump when they hit a sensitive asset.
_HIGH_IMPACT = {"lateral_movement", "credential_misuse"}


def compute_severity(risk_score: float, resource_sensitivity: float | int | None,
                     predicted_label: str | None = None) -> tuple[str, float]:
    """Blend anomaly risk (0-1) with asset sensitivity (1-5) into a 0-1
    severity score, then bucket. Returns (level, score)."""
    sens = (float(resource_sensitivity) if resource_sensitivity else 1.0) / 5.0
    score = 0.65 * float(risk_score) + 0.35 * sens
    if predicted_label in _HIGH_IMPACT and sens >= 0.8:
        score = min(1.0, score + 0.10)   # sensitive-asset escalation

    if score >= 0.80:
        level = "Critical"
    elif score >= 0.60:
        level = "High"
    elif score >= 0.40:
        level = "Medium"
    else:
        level = "Low"
    return level, round(score, 3)


def recommend_actions(predicted_label: str | None, severity: str) -> list[str]:
    actions = list(RESPONSE_MAP.get(predicted_label, ["Review the alert manually", "Require MFA"]))
    if severity == "Critical":
        actions = ["Page the on-call SOC analyst"] + actions
    return actions


def enrich_alert(risk_score: float, predicted_label: str | None,
                 resource_sensitivity: float | int | None) -> dict:
    """One call to attach severity + MITRE + recommended response to an alert."""
    severity, sev_score = compute_severity(risk_score, resource_sensitivity, predicted_label)
    return {
        "severity": severity,
        "severity_score": sev_score,
        "mitre": MITRE_MAP.get(predicted_label),
        "recommended_actions": recommend_actions(predicted_label, severity),
    }


if __name__ == "__main__":
    for r, lbl, sens in [(0.95, "lateral_movement", 5), (0.62, "brute_force", 3),
                         (0.71, "impossible_travel", 3), (0.4, "device_spoofing", 5)]:
        e = enrich_alert(r, lbl, sens)
        print(f"risk={r} {lbl:18s} sens={sens} -> {e['severity']:8s} "
              f"{e['mitre']['technique_id']} {e['mitre']['tactic']:20s} {e['recommended_actions']}")