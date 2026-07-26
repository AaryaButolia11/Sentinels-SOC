"""
Synthetic Access Log Generator
==============================

Generates a realistic-looking stream of user/device access events with
a population of "normal" users, then injects five labeled attack
patterns into the timeline:

  1. credential_misuse   - legit creds used to touch resources far outside
                            the user's normal behavior profile
  2. brute_force         - rapid-fire failed auth attempts, short window
  3. lateral_movement    - fast hopping across multiple resources/hosts,
                            escalating privilege, after an initial foothold
  4. impossible_travel   - same user "logs in" from two geo-distant
                            locations within a physically impossible time
  5. device_spoofing     - a device claims a known device's identity but
                            with mismatched/inconsistent fingerprint signals

Ground-truth labels are attached to every event so you can train/evaluate
supervised models and measure precision/recall later. At inference time
in the real pipeline, you'd strip the `label` field before scoring.

Usage:
    python generate_logs.py --users 60 --days 14 --out sample_logs.csv
"""

import argparse
import csv
import os
import random
import sys
import uuid
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from data.schemas import AccessEvent, ATTACK_TYPES

RESOURCES = [
    ("email", 1),
    ("intranet_wiki", 1),
    ("shared_drive", 2),
    ("crm", 2),
    ("finance_share", 4),
    ("hr_db", 4),
    ("vpn", 3),
    ("admin_console", 5),
    ("source_repo", 3),
    ("payment_gateway", 5),
]

# "Home" cities: where legitimate users normally sign in from. Kept diverse
# across regions/timezones so normal traffic isn't clustered either.
HOME_CITIES = [
    ("Bengaluru", 12.9716, 77.5946, "IN"),
    ("Mumbai", 19.0760, 72.8777, "IN"),
    ("Delhi", 28.7041, 77.1025, "IN"),
    ("Singapore", 1.3521, 103.8198, "SG"),
    ("London", 51.5074, -0.1278, "GB"),
    ("New York", 40.7128, -74.0060, "US"),
    ("Frankfurt", 50.1109, 8.6821, "DE"),
    ("Sydney", -33.8688, 151.2093, "AU"),
    ("Toronto", 43.6532, -79.3832, "CA"),
    ("São Paulo", -23.5505, -46.6333, "BR"),
]

# "Attacker" origin cities: atypical locations used for brute_force and
# device_spoofing. Deliberately a large, globally-spread pool (not just
# 1-2 cities) so the threat map doesn't collapse onto the same couple of
# arcs every run — random.choice() picks uniformly across all of these.
ATTACKER_CITIES = [
    ("Moscow", 55.7558, 37.6173, "RU"),
    ("Lagos", 6.5244, 3.3792, "NG"),
    ("Johannesburg", -26.2041, 28.0473, "ZA"),
    ("Dubai", 25.2048, 55.2708, "AE"),
    ("Tehran", 35.6892, 51.3890, "IR"),
    ("Beijing", 39.9042, 116.4074, "CN"),
    ("Jakarta", -6.2088, 106.8456, "ID"),
    ("Bucharest", 44.4268, 26.1025, "RO"),
    ("Manila", 14.5995, 120.9842, "PH"),
    ("Buenos Aires", -34.6037, -58.3816, "AR"),
    ("Karachi", 24.8607, 67.0011, "PK"),
    ("Kyiv", 50.4501, 30.5234, "UA"),
]

# Full pool (used by impossible_travel, which is fine picking from anywhere).
CITIES = HOME_CITIES + ATTACKER_CITIES


def haversine_km(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, sqrt, atan2
    R = 6371.0
    p1, p2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(p1) * cos(p2) * sin(dlambda / 2) ** 2
    return 2 * R * atan2(sqrt(a), sqrt(1 - a))


class User:
    """Holds a synthetic user's normal behavioral baseline."""

    def __init__(self, user_id):
        self.user_id = user_id
        self.home_city = random.choice(HOME_CITIES)  # legitimate users only ever start here
        self.devices = [f"dev-{uuid.uuid4().hex[:8]}" for _ in range(random.choice([1, 1, 2]))]
        self.typical_hours = sorted(random.sample(range(6, 21), k=6))  # 6 active hours/day
        # Each user has 2-4 resources they normally touch, weighted by role
        self.typical_resources = random.sample(RESOURCES, k=random.choice([2, 3, 4]))

    def random_normal_hour(self):
        return random.choice(self.typical_hours)

    def random_normal_resource(self):
        return random.choice(self.typical_resources)

    def random_ip_near_home(self):
        # crude synthetic IP tied loosely to "home" for flavor
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def gen_normal_event(user: User, ts: datetime) -> AccessEvent:
    resource, sensitivity = user.random_normal_resource()
    device = random.choice(user.devices)
    city_name, lat, lon, country = user.home_city
    return AccessEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts,
        user_id=user.user_id,
        device_id=device,
        ip_address=user.random_ip_near_home(),
        geo_lat=lat + random.uniform(-0.05, 0.05),
        geo_lon=lon + random.uniform(-0.05, 0.05),
        geo_country=country,
        action=random.choice(["login", "file_access", "read", "query"]),
        resource=resource,
        resource_sensitivity=sensitivity,
        auth_result="success",
        session_duration_s=random.randint(60, 3600),
        is_new_device=False,
        label="none",
    )


def inject_credential_misuse(user: User, ts: datetime) -> list[AccessEvent]:
    """Legit-looking login but touching a highly sensitive resource the
    user never normally accesses, often at an odd hour."""
    odd_hour_ts = ts.replace(hour=random.choice([1, 2, 3, 4]))
    resource, sensitivity = random.choice([r for r in RESOURCES if r[1] >= 4])
    city_name, lat, lon, country = user.home_city
    ev = AccessEvent(
        event_id=str(uuid.uuid4()),
        timestamp=odd_hour_ts,
        user_id=user.user_id,
        device_id=random.choice(user.devices),
        ip_address=user.random_ip_near_home(),
        geo_lat=lat,
        geo_lon=lon,
        geo_country=country,
        action="privilege_escalation",
        resource=resource,
        resource_sensitivity=sensitivity,
        auth_result="success",
        session_duration_s=random.randint(30, 300),
        is_new_device=False,
        label="credential_misuse",
    )
    return [ev]


def inject_brute_force(user: User, ts: datetime) -> list[AccessEvent]:
    """Rapid-fire failed logins in a tight window, occasionally ending
    in a success (compromise)."""
    events = []
    attacker_city = random.choice(ATTACKER_CITIES)  # atypical origin, evenly spread pool
    _, lat, lon, country = attacker_city
    n_attempts = random.randint(8, 25)
    cur = ts
    for i in range(n_attempts):
        cur = cur + timedelta(seconds=random.randint(2, 8))
        success = (i == n_attempts - 1) and random.random() < 0.3
        events.append(AccessEvent(
            event_id=str(uuid.uuid4()),
            timestamp=cur,
            user_id=user.user_id,
            device_id=f"dev-{uuid.uuid4().hex[:8]}",  # unknown device
            ip_address=f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            geo_lat=lat,
            geo_lon=lon,
            geo_country=country,
            action="login",
            resource="vpn",
            resource_sensitivity=3,
            auth_result="success" if success else "failure",
            session_duration_s=None,
            is_new_device=True,
            label="brute_force",
        ))
    return events


def inject_lateral_movement(user: User, ts: datetime) -> list[AccessEvent]:
    """Fast hopping across many resources with increasing sensitivity,
    simulating an attacker pivoting after an initial foothold."""
    events = []
    device = random.choice(user.devices)
    city_name, lat, lon, country = user.home_city
    cur = ts
    hop_resources = sorted(RESOURCES, key=lambda r: r[1])  # ascending sensitivity
    for resource, sensitivity in hop_resources[-6:]:
        cur = cur + timedelta(seconds=random.randint(15, 90))
        events.append(AccessEvent(
            event_id=str(uuid.uuid4()),
            timestamp=cur,
            user_id=user.user_id,
            device_id=device,
            ip_address=user.random_ip_near_home(),
            geo_lat=lat,
            geo_lon=lon,
            geo_country=country,
            action="query" if sensitivity < 4 else "privilege_escalation",
            resource=resource,
            resource_sensitivity=sensitivity,
            auth_result="success",
            session_duration_s=random.randint(10, 60),
            is_new_device=False,
            label="lateral_movement",
        ))
    return events


def inject_impossible_travel(user: User, ts: datetime) -> list[AccessEvent]:
    """Two logins by the same user from geographically distant locations
    within a physically impossible time window."""
    home_city_name, home_lat, home_lon, home_country = user.home_city
    far_city = random.choice([c for c in CITIES if c[0] != home_city_name])
    far_name, far_lat, far_lon, far_country = far_city

    first = AccessEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts,
        user_id=user.user_id,
        device_id=random.choice(user.devices),
        ip_address=user.random_ip_near_home(),
        geo_lat=home_lat,
        geo_lon=home_lon,
        geo_country=home_country,
        action="login",
        resource="vpn",
        resource_sensitivity=3,
        auth_result="success",
        session_duration_s=120,
        is_new_device=False,
        label="impossible_travel",
    )
    # Distance implies >> feasible travel speed within this gap
    gap_minutes = random.randint(10, 45)
    second = AccessEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts + timedelta(minutes=gap_minutes),
        user_id=user.user_id,
        device_id=random.choice(user.devices),
        ip_address=f"41.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        geo_lat=far_lat,
        geo_lon=far_lon,
        geo_country=far_country,
        action="login",
        resource="vpn",
        resource_sensitivity=3,
        auth_result="success",
        session_duration_s=90,
        is_new_device=False,
        label="impossible_travel",
    )
    return [first, second]


def inject_device_spoofing(user: User, ts: datetime) -> list[AccessEvent]:
    """A device claims to be a known trusted device_id but with
    inconsistent fingerprint signals (different geo/IP block than that
    device has ever used, at an unusual hour)."""
    spoofed_device = random.choice(user.devices)  # claims known device
    city_name, lat, lon, country = random.choice(ATTACKER_CITIES)  # atypical geo, evenly spread pool
    ev = AccessEvent(
        event_id=str(uuid.uuid4()),
        timestamp=ts.replace(hour=random.choice([0, 2, 3])),
        user_id=user.user_id,
        device_id=spoofed_device,
        ip_address=f"91.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        geo_lat=lat,
        geo_lon=lon,
        geo_country=country,
        action="login",
        resource="admin_console",
        resource_sensitivity=5,
        auth_result="success",
        session_duration_s=45,
        is_new_device=False,  # claims to be a known device -> that's the spoof
        label="device_spoofing",
    )
    return [ev]


ATTACK_INJECTORS = {
    "credential_misuse": inject_credential_misuse,
    "brute_force": inject_brute_force,
    "lateral_movement": inject_lateral_movement,
    "impossible_travel": inject_impossible_travel,
    "device_spoofing": inject_device_spoofing,
}


def generate_dataset(n_users=80, n_days=30, events_per_user_per_day=8,
                      attack_prob_per_user_per_day=0.10, seed=42):
    random.seed(seed)
    users = [User(f"user-{i:03d}") for i in range(n_users)]
    start = datetime(2026, 7, 1, 0, 0, 0)

    all_events: list[AccessEvent] = []

    for day in range(n_days):
        day_start = start + timedelta(days=day)
        for user in users:
            # Normal daily activity
            for _ in range(events_per_user_per_day):
                hour = user.random_normal_hour()
                minute = random.randint(0, 59)
                ts = day_start.replace(hour=hour, minute=minute)
                all_events.append(gen_normal_event(user, ts))

            # Chance of an attack pattern touching this user today
            if random.random() < attack_prob_per_user_per_day:
                attack_type = random.choice(list(ATTACK_INJECTORS.keys()))
                base_ts = day_start.replace(
                    hour=random.randint(0, 23), minute=random.randint(0, 59)
                )
                all_events.extend(ATTACK_INJECTORS[attack_type](user, base_ts))

    all_events.sort(key=lambda e: e.timestamp)
    return all_events


def save_csv(events: list[AccessEvent], path: str):
    if not events:
        return
    fieldnames = list(events[0].to_dict().keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            writer.writerow(ev.to_dict())


def print_summary(events: list[AccessEvent]):
    from collections import Counter
    counts = Counter(e.label for e in events)
    total = len(events)
    print(f"Total events generated: {total}")
    for label in ATTACK_TYPES:
        c = counts.get(label, 0)
        pct = 100 * c / total if total else 0
        print(f"  {label:20s}: {c:6d}  ({pct:.3f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=80)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--events_per_user_per_day", type=int, default=8)
    parser.add_argument("--attack_prob", type=float, default=0.10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="sample_logs.csv")
    args = parser.parse_args()

    events = generate_dataset(
        n_users=args.users,
        n_days=args.days,
        events_per_user_per_day=args.events_per_user_per_day,
        attack_prob_per_user_per_day=args.attack_prob,
        seed=args.seed,
    )
    print_summary(events)
    save_csv(events, args.out)
    print(f"Saved to {args.out}")