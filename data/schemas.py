"""
Schema definitions for access log events.

Each event represents one access/authentication action by a user,
from a device, at a location, at a point in time.
"""
from dataclasses import dataclass, asdict
from typing import Optional

ATTACK_TYPES = [
    "none",                 # normal traffic
    "credential_misuse",
    "brute_force",
    "lateral_movement",
    "impossible_travel",
    "device_spoofing",
]


@dataclass
class AccessEvent:
    event_id: str
    timestamp: object  # datetime
    user_id: str
    device_id: str
    ip_address: str
    geo_lat: float
    geo_lon: float
    geo_country: str
    action: str                 # e.g. "login", "file_access", "privilege_escalation"
    resource: str                # e.g. "hr_db", "vpn", "finance_share", "admin_console"
    resource_sensitivity: int    # 1 (low) - 5 (critical)
    auth_result: str             # "success" | "failure"
    session_duration_s: Optional[int] = None
    is_new_device: bool = False
    # Ground truth label (used only for training/eval, NOT fed to the
    # unsupervised anomaly model at inference time)
    label: str = "none"          # one of ATTACK_TYPES

    def to_dict(self):
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d