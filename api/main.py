"""
api/main.py
===========
FastAPI app entrypoint.

Startup:
  1. Load events from data/sample_logs.csv.
  2. Train the Pipeline (anomaly scorer + classifier) on the first 80%.
  3. Pre-score the held-out 20% "live" slice IN TRUE TIME ORDER (correct
     stateful scoring), then build an interleaved emission sequence so that
     alerts + threat arcs start showing within the first second instead of
     after a long lead-in of normal traffic. All 155-ish real alerts are kept;
     normals are thinned to a steady ~2:1 ratio.

Signing in as admin (POST /auth/admin/login) — or POST /replay/start — clears
the tables and streams that pre-scored sequence to the DB + /ws/alerts, exactly
the endpoints the dashboard already reads. Nothing is hardcoded in the frontend;
everything originates from the CSV through the real pipeline.

Run with:  uvicorn api.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations
import asyncio
import csv
import os
import sys
import time
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "streaming"))

from feature_engineering import build_feature_table
from pipeline import Pipeline

from .db.init_db import init_db, SessionLocal
from .db.models import EventDB, AlertDB
from .routes import alerts, feedback, stream, copilot, investigation, remediation
from .routes.users import router as users_router
from . import state

app = FastAPI(title="Behavioral Anomaly Detection API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(alerts.router)
app.include_router(feedback.router)
app.include_router(stream.router)
app.include_router(users_router)
app.include_router(copilot.router)
app.include_router(investigation.router)
app.include_router(remediation.router)

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")

STREAM_DELAY_SECONDS = 0.15   # per emitted event -> ~1 arc every ~0.45s
ANOMALY_THRESHOLD = 0.6       # 0.6 keeps false positives ~0; drop to 0.55 for even more alerts
NORMALS_PER_ALERT = 2         # emission ratio: how many routine events shown between alerts
# Cap how many live events get pre-scored at startup. Pre-scoring runs SHAP on
# every flagged event, which is the slow part — on a large dataset (tens of
# thousands of events) that can take minutes. Capping the live slice keeps
# startup to a few seconds and keeps the replay a sensible demo length. Raise
# this if you want a longer run and don't mind a slower first startup.
MAX_LIVE_EVENTS = 1000

# The dashboard's severity strip does an exact-match count against these four
# labels (see /metrics and /dashboard/overview below). enrich_alert() is free
# to return other casings/spellings ("critical", "HIGH", "med", ...), so every
# severity gets normalized to one of these canonical labels the moment an
# Alert is turned into DB/broadcast fields — never stored/counted raw.
SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low")
_SEVERITY_ALIASES = {
    "critical": "Critical", "crit": "Critical", "p1": "Critical",
    "high": "High", "p2": "High",
    "medium": "Medium", "med": "Medium", "moderate": "Medium", "p3": "Medium",
    "low": "Low", "p4": "Low", "info": "Low", "informational": "Low",
}


def _canon_severity(raw, risk_score: float | None = None) -> str:
    """Map any severity spelling/casing to one of SEVERITY_LEVELS. Falls back
    to deriving a bucket from risk_score if the value is missing/unrecognized,
    so the strip never silently sticks at zero because of a label mismatch."""
    if raw:
        hit = _SEVERITY_ALIASES.get(str(raw).strip().lower())
        if hit:
            return hit
    r = risk_score or 0.0
    if r >= 0.85:
        return "Critical"
    if r >= 0.7:
        return "High"
    if r >= 0.6:
        return "Medium"
    return "Low"


pipeline: Pipeline | None = None

# ---- replay orchestration ----
_replay_records: list[tuple[dict, object]] = []   # pre-scored (event, alert-or-None), emission order
_replay_task: asyncio.Task | None = None
_replay_stats = {"running": False, "processed": 0, "alerts": 0, "total": 0, "started_at": None}

FEATURE_CATEGORY = {
    "geo_distance_from_home_km": "Location", "geo_velocity_kmh": "Location",
    "is_new_country": "Location", "is_new_ip": "Location", "new_ip_ratio": "Location",
    "peer_group_deviation": "Location",
    "is_new_device": "Device", "device_familiarity": "Device", "distinct_device_count": "Device",
    "hour_of_day": "Time", "hour_typicality": "Time", "seconds_since_last_event": "Time",
    "auth_failed": "Credential", "failed_attempts_last_5min": "Credential",
    "failed_login_ratio": "Credential", "is_privilege_escalation_action": "Credential",
    "resource_sensitivity": "Behavior", "resource_familiarity": "Behavior",
    "session_duration_s": "Behavior", "session_duration_deviation": "Behavior",
    "baseline_confidence": "Behavior",
}
_COUNTRY_XY = {
    "IN": (0.75, 0.62), "SG": (0.83, 0.48), "GB": (0.47, 0.30), "US": (0.18, 0.35),
    "DE": (0.52, 0.32), "AU": (0.88, 0.80), "RU": (0.62, 0.24), "NG": (0.48, 0.60),
    "CA": (0.28, 0.26), "BR": (0.37, 0.63),   # home cities: Toronto, São Paulo
    "ZA": (0.58, 0.65), "AE": (0.65, 0.36), "IR": (0.64, 0.30), "CN": (0.82, 0.28),
    "ID": (0.80, 0.53), "RO": (0.57, 0.25), "PH": (0.84, 0.42), "AR": (0.34, 0.69),
    "PK": (0.69, 0.36), "UA": (0.58, 0.22),   # attacker cities
}


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminLoginResponse(BaseModel):
    ok: bool
    token: str
    user: dict


def _load_events(path):
    events = []
    with open(path) as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["resource_sensitivity"] = int(row["resource_sensitivity"])
            row["geo_lat"] = float(row["geo_lat"])
            row["geo_lon"] = float(row["geo_lon"])
            row["session_duration_s"] = (
                int(row["session_duration_s"]) if row["session_duration_s"] not in ("", "None") else None
            )
            events.append(row)
    return events


def _clear_tables():
    db = SessionLocal()
    try:
        db.query(AlertDB).delete()
        db.query(EventDB).delete()
        db.commit()
    finally:
        db.close()


def _prescore_and_order(live_events: list[dict]) -> list[tuple[dict, object]]:
    """Score the live slice in TRUE time order (so stateful features like
    failed_attempts_last_5min and geo_velocity are correct), then reorder for
    presentation: keep every real alert, thin the normals, and interleave so the
    first arc appears within the first second and the cadence stays steady.
    Reordering only affects *display* — every score was computed in correct order.
    """
    global pipeline
    records = [(ev, pipeline.process(ev)) for ev in live_events]
    flagged = [r for r in records if r[1] is not None]
    normal = [r for r in records if r[1] is None]

    if not flagged:
        return records  # nothing flagged (tiny/odd dataset) -> just replay as-is

    keep_every = max(1, len(normal) // (NORMALS_PER_ALERT * len(flagged)))
    kept_normals = normal[::keep_every]

    emission: list[tuple[dict, object]] = []
    ni = ai = 0
    while ai < len(flagged) or ni < len(kept_normals):
        for _ in range(NORMALS_PER_ALERT):
            if ni < len(kept_normals):
                emission.append(kept_normals[ni]); ni += 1
        if ai < len(flagged):
            emission.append(flagged[ai]); ai += 1
    return emission


async def _replay_loop(records: list[tuple[dict, object]]):
    """Emit the pre-scored sequence: persist each event/alert and broadcast it
    to /ws/alerts subscribers on a steady cadence.

    Each record is handled defensively: a malformed Alert (e.g. missing an
    attribute the classifier/enrichment step didn't set) must never kill this
    task, since it runs once as a background asyncio.Task with nobody
    awaiting it — an uncaught exception here silently stops the entire
    live stream for the rest of the process lifetime.
    """
    global _replay_stats
    _replay_stats.update(running=True, processed=0, alerts=0,
                         total=len(records), started_at=datetime.utcnow().isoformat())

    for ev, alert in records:
        _replay_stats["processed"] += 1

        # Build a safe view of the alert's fields up front. getattr(...) with
        # a default means a missing attribute degrades gracefully (e.g. no
        # MITRE mapping) instead of raising and aborting the whole replay.
        alert_fields = None
        if alert:
            mitre = getattr(alert, "mitre", None) or {}
            explanation = getattr(alert, "explanation", None) or {}
            alert_fields = {
                "alert_id": getattr(alert, "alert_id", ev["event_id"]),
                "risk_score": getattr(alert, "risk_score", None),
                "predicted_label": getattr(alert, "predicted_label", None),
                "label_confidence": getattr(alert, "label_confidence", None),
                "explanation_sentence": explanation.get("sentence") if isinstance(explanation, dict) else None,
                "explanation_top_features": explanation.get("top_features") if isinstance(explanation, dict) else None,
                "severity": _canon_severity(getattr(alert, "severity", None), getattr(alert, "risk_score", None)),
                "severity_score": getattr(alert, "severity_score", None),
                "mitre": mitre,
                "recommended_actions": getattr(alert, "recommended_actions", None) or [],
            }

        db = SessionLocal()
        try:
            raw_serializable = {**ev, "timestamp": ev["timestamp"].isoformat()}
            if not db.query(EventDB).filter(EventDB.event_id == ev["event_id"]).first():
                db.add(EventDB(
                    event_id=ev["event_id"], user_id=ev["user_id"], device_id=ev["device_id"],
                    timestamp=ev["timestamp"], resource=ev["resource"], action=ev["action"],
                    raw=raw_serializable,
                ))
            if alert_fields:
                _replay_stats["alerts"] += 1
                if not db.query(AlertDB).filter(AlertDB.alert_id == alert_fields["alert_id"]).first():
                    db.add(AlertDB(
                        alert_id=alert_fields["alert_id"], event_id=ev["event_id"], user_id=ev["user_id"],
                        risk_score=alert_fields["risk_score"], predicted_label=alert_fields["predicted_label"],
                        label_confidence=alert_fields["label_confidence"],
                        explanation_sentence=alert_fields["explanation_sentence"],
                        explanation_top_features=alert_fields["explanation_top_features"],
                        severity=alert_fields["severity"], severity_score=alert_fields["severity_score"],
                        mitre_technique_id=alert_fields["mitre"].get("technique_id"),
                        mitre_technique=alert_fields["mitre"].get("technique"),
                        mitre_tactic=alert_fields["mitre"].get("tactic"),
                        recommended_actions=alert_fields["recommended_actions"],
                    ))
            db.commit()
        except IntegrityError:
            db.rollback()
        except Exception as exc:
            # Log and move on to the next record instead of propagating —
            # this task has no caller to catch/report the exception, so a
            # `raise` here would permanently end the live stream.
            db.rollback()
            print(f"[replay] skipped record {ev.get('event_id')}: {exc!r}")
        finally:
            db.close()

        try:
            if alert_fields:
                await stream.manager.broadcast({
                    "type": "alert",
                    "alert_id": alert_fields["alert_id"],
                    "user_id": ev["user_id"],
                    "device_id": ev["device_id"],
                    "resource": ev["resource"],
                    "action": ev["action"],
                    "geo_country": ev.get("geo_country"),
                    "geo_lat": ev.get("geo_lat"),
                    "geo_lon": ev.get("geo_lon"),
                    "ip_address": ev.get("ip_address"),
                    "timestamp": ev["timestamp"].isoformat(),
                    "risk_score": alert_fields["risk_score"],
                    "predicted_label": alert_fields["predicted_label"],
                    "label_confidence": alert_fields["label_confidence"],
                    "explanation": alert_fields["explanation_sentence"],
                    "top_features": alert_fields["explanation_top_features"],
                    "severity": alert_fields["severity"],
                    "severity_score": alert_fields["severity_score"],
                    "mitre": alert_fields["mitre"],
                    "recommended_actions": alert_fields["recommended_actions"],
                    "true_label": ev.get("label", "none"),
                })
            else:
                await stream.manager.broadcast({
                    "type": "heartbeat",
                    "user_id": ev["user_id"], "resource": ev["resource"], "action": ev["action"],
                    "geo_country": ev.get("geo_country"),
                    "geo_lat": ev.get("geo_lat"), "geo_lon": ev.get("geo_lon"),
                    "timestamp": ev["timestamp"].isoformat(),
                })
        except Exception as exc:
            print(f"[replay] broadcast failed for {ev.get('event_id')}: {exc!r}")

        await asyncio.sleep(STREAM_DELAY_SECONDS)

    _replay_stats["running"] = False



def _start_replay() -> dict:
    """(Re)start the live replay from a clean slate. Called on admin sign-in
    and by POST /replay/start. Must be invoked from the event loop."""
    global _replay_task
    if pipeline is None or not _replay_records:
        raise HTTPException(status_code=503, detail="Pipeline not ready yet — try again in a moment.")
    if _replay_task and not _replay_task.done():
        _replay_task.cancel()
    _clear_tables()
    _replay_task = asyncio.create_task(_replay_loop(_replay_records))
    return {"started": True, "events_to_replay": len(_replay_records)}


async def _build_pipeline_in_background():
    """Heavy one-time setup: feature build -> train both models -> pre-score
    the live slice (SHAP explanations) -> auto-start the replay.

    This is all CPU-bound and synchronous, so it runs in worker threads via
    asyncio.to_thread. That keeps the event loop free and lets uvicorn report
    'Application startup complete' immediately, instead of appearing to hang on
    'Waiting for application startup.' while the models train. Every phase logs
    with a timestamp so you can watch progress in the console.
    """
    global pipeline, _replay_records, _replay_task
    t0 = time.time()
    try:
        all_events = _load_events(DATA_PATH)
        split = int(len(all_events) * 0.8)
        train_events, live_events = all_events[:split], all_events[split:]
        # Bound the pre-scoring work (SHAP) so startup stays fast on large data.
        if len(live_events) > MAX_LIVE_EVENTS:
            live_events = live_events[:MAX_LIVE_EVENTS]
        print(f"[startup] loaded {len(all_events)} events "
              f"({len(train_events)} train / {len(live_events)} live "
              f"[capped at {MAX_LIVE_EVENTS}])", flush=True)

        feature_rows, labels, store = await asyncio.to_thread(build_feature_table, train_events)
        print(f"[startup] features built ({time.time() - t0:.1f}s)", flush=True)

        pipeline = await asyncio.to_thread(
            lambda: Pipeline(anomaly_threshold=ANOMALY_THRESHOLD).fit(feature_rows, labels, store)
        )
        state.set_pipeline(pipeline)
        print(f"[startup] models trained ({time.time() - t0:.1f}s)", flush=True)

        # This is usually the slow part — SHAP runs here, per flagged event.
        print("[startup] pre-scoring live slice (SHAP explanations)…", flush=True)
        _replay_records = await asyncio.to_thread(_prescore_and_order, live_events)
        n_alerts = sum(1 for _, a in _replay_records if a)
        print(f"[startup] pre-scored: emission={len(_replay_records)} alerts={n_alerts} "
              f"({time.time() - t0:.1f}s)", flush=True)

        _replay_task = asyncio.create_task(_replay_loop(_replay_records))
        print(f"[startup] replay started — dashboard is live ({time.time() - t0:.1f}s)", flush=True)
    except Exception as exc:
        # Never let a startup error vanish silently — surface it in the console.
        import traceback
        print(f"[startup] FAILED after {time.time() - t0:.1f}s: {exc!r}", flush=True)
        traceback.print_exc()


@app.on_event("startup")
async def startup():
    init_db()
    _clear_tables()

    if not os.path.exists(DATA_PATH):
        raise RuntimeError(
            f"No data at {DATA_PATH}. Run `python data/generate_logs.py --out data/sample_logs.csv` first."
        )

    # Kick the heavy build off in the background so the server reports ready
    # right away. /metrics and the dashboard already tolerate "not ready yet"
    # and fill in as soon as the pipeline finishes training.
    asyncio.create_task(_build_pipeline_in_background())


@app.post("/auth/admin/login", response_model=AdminLoginResponse)
async def admin_login(payload: AdminLoginRequest):
    # MUST be async: _start_replay() calls asyncio.create_task, which only works
    # on the event loop. A sync endpoint runs in a worker thread with no loop and
    # the replay would silently never start.
    if payload.username == "admin" and payload.password == "admin123":
        try:
            _start_replay()
        except HTTPException:
            pass  # still training; frontend can retry POST /replay/start
        return {"ok": True, "token": "demo-admin-token",
                "user": {"username": "admin", "role": "admin", "name": "Aarya Singh"}}
    raise HTTPException(status_code=401, detail="Invalid admin credentials")


@app.post("/replay/start")
async def replay_start():
    return _start_replay()


@app.get("/replay/status")
def replay_status():
    return _replay_stats


@app.get("/health")
def health():
    return {"status": "ok", "pipeline_ready": pipeline is not None,
            "replay_ready": bool(_replay_records), "replay": _replay_stats}


@app.get("/metrics")
def metrics():
    if pipeline is None or pipeline.classifier is None:
        return {"ready": False}
    results = pipeline.classifier.evaluate()
    db = SessionLocal()
    try:
        n_events = db.query(EventDB).count()
        n_alerts = db.query(AlertDB).count()
        n_active_users = db.query(EventDB.user_id).distinct().count()
        avg_risk = db.query(func.avg(AlertDB.risk_score)).scalar()
        avg_conf = db.query(func.avg(AlertDB.label_confidence)).scalar()
        severity_breakdown = {
            level: db.query(AlertDB).filter(func.lower(AlertDB.severity) == level.lower()).count()
            for level in SEVERITY_LEVELS
        }
    finally:
        db.close()
    try:
        from .routes.feedback import drift_monitor
        rolling_fp = drift_monitor.status().get("rolling_fp_rate")
    except Exception:
        rolling_fp = None
    return {
        "ready": True,
        "macro_precision": results["macro_precision"],
        "macro_recall": results["macro_recall"],
        "macro_f1": results["macro_f1"],
        "per_class": {
            cls: {
                "precision": results["per_class_report"][cls]["precision"],
                "recall": results["per_class_report"][cls]["recall"],
                "f1": results["per_class_report"][cls]["f1-score"],
                "support": results["per_class_report"][cls]["support"],
            } for cls in pipeline.classifier.classes_
        },
        "events_processed": n_events,
        "alerts_raised": n_alerts,
        "alert_rate": (n_alerts / n_events) if n_events else 0.0,
        "threats_today": n_alerts,
        "active_users": n_active_users,
        "avg_risk_score": round((avg_risk or 0.0) * 100, 1),
        "detection_accuracy": round(results["macro_f1"] * 100, 1),
        "false_positive_rate": round((rolling_fp or 0.0) * 100, 1),
        "ai_confidence": round((avg_conf or 0.0) * 100),
        "severity_breakdown": severity_breakdown,
        "replay": _replay_stats,
    }


@app.get("/dashboard/overview")
def dashboard_overview():
    db = SessionLocal()
    try:
        recent = db.query(AlertDB).order_by(AlertDB.created_at.desc()).limit(50).all()
        shown = recent[:8]
        classification = [
            {"name": lbl or "unknown", "value": cnt}
            for lbl, cnt in db.query(AlertDB.predicted_label, func.count(AlertDB.alert_id))
                              .group_by(AlertDB.predicted_label).all()
        ]
        severity_breakdown = {
            level: db.query(AlertDB).filter(func.lower(AlertDB.severity) == level.lower()).count()
            for level in SEVERITY_LEVELS
        }
        event_ids = [a.event_id for a in recent]
        country_counts = {}
        if event_ids:
            for ev in db.query(EventDB).filter(EventDB.event_id.in_(event_ids)).all():
                c = (ev.raw or {}).get("geo_country")
                if c:
                    country_counts[c] = country_counts.get(c, 0) + 1
        map_nodes = [
            {"name": c, "type": "attack", "count": n,
             "x": _COUNTRY_XY.get(c, (0.5, 0.5))[0], "y": _COUNTRY_XY.get(c, (0.5, 0.5))[1]}
            for c, n in sorted(country_counts.items(), key=lambda kv: -kv[1])
        ]
        cat_totals = {"Location": 0.0, "Device": 0.0, "Time": 0.0, "Credential": 0.0, "Behavior": 0.0}
        for a in recent:
            for tf in (a.explanation_top_features or []):
                cat = FEATURE_CATEGORY.get(tf.get("feature"))
                if cat:
                    cat_totals[cat] += abs(float(tf.get("contribution", 0.0)))
        peak = max(cat_totals.values()) or 1.0
        risk_breakdown = [{"name": k, "value": round(100 * v / peak)} for k, v in cat_totals.items()]
        timeline = [
            {"time": a.created_at.strftime("%H:%M") if a.created_at else "--:--",
             "label": (a.predicted_label or "unknown").replace("_", " ").title(),
             "severity": a.severity,
             "intensity": max(1, min(5, round((a.severity_score or 0.0) * 5)))}
            for a in shown
        ]
        alerts_out = [
            {"alert_id": a.alert_id, "user_id": a.user_id,
             "predicted_label": a.predicted_label, "risk_score": a.risk_score,
             "severity": a.severity,
             "mitre": {"technique_id": a.mitre_technique_id, "technique": a.mitre_technique,
                       "tactic": a.mitre_tactic},
             "recommended_actions": a.recommended_actions or [],
             "explanation": a.explanation_sentence}
            for a in shown
        ]
    finally:
        db.close()
    return {"timeline": timeline, "map_nodes": map_nodes, "risk_breakdown": risk_breakdown,
            "classification": classification, "severity_breakdown": severity_breakdown, "alerts": alerts_out}


@app.get("/dashboard/trend")
def dashboard_trend(limit: int = 40):
    db = SessionLocal()
    try:
        rows = (db.query(AlertDB).order_by(AlertDB.created_at.desc()).limit(limit).all())[::-1]
        points = [
            {"t": a.created_at.strftime("%H:%M:%S") if a.created_at else "",
             "risk": round(a.risk_score or 0.0, 3), "severity": a.severity, "label": a.predicted_label}
            for a in rows
        ]
    finally:
        db.close()
    window, avg = 5, []
    for i in range(len(points)):
        seg = [p["risk"] for p in points[max(0, i - window + 1): i + 1]]
        avg.append(round(sum(seg) / len(seg), 3))
    for p, a in zip(points, avg):
        p["risk_avg"] = a
    return {"points": points}


@app.get("/dashboard/attack-replay")
def dashboard_attack_replay(limit: int = 30):
    db = SessionLocal()
    try:
        recent = db.query(AlertDB).order_by(AlertDB.created_at.desc()).limit(limit).all()
        event_ids = [a.event_id for a in recent]
        events_by_id = {}
        if event_ids:
            events_by_id = {e.event_id: e for e in db.query(EventDB).filter(EventDB.event_id.in_(event_ids)).all()}
        arcs = []
        for a in reversed(recent):
            ev = events_by_id.get(a.event_id)
            raw = (ev.raw if ev else {}) or {}
            lat, lon = raw.get("geo_lat"), raw.get("geo_lon")
            if lat is None or lon is None:
                continue
            arcs.append({"source": {"lat": lat, "lon": lon}, "label": a.predicted_label, "risk_score": a.risk_score})
    finally:
        db.close()
    return {"hq": {"lat": 12.9716, "lon": 77.5946}, "arcs": arcs}


if os.path.isdir(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR, html=True), name="static")

    @app.get("/dashboard/styles.css")
    def dashboard_styles():
        return FileResponse(os.path.join(DASHBOARD_DIR, "styles.css"))

    @app.get("/dashboard/app.js")
    def dashboard_app_js():
        return FileResponse(os.path.join(DASHBOARD_DIR, "app.js"))

    @app.get("/dashboard/{path:path}")
    def dashboard_redirect(path: str):
        if path == "overview":
            raise HTTPException(status_code=404)
        return RedirectResponse(url=f"/static/{path}")

    @app.get("/login")
    def login_page():
        # Dedicated login page. The dashboard ("/") is guarded client-side and
        # redirects here when there's no active session.
        return FileResponse(os.path.join(DASHBOARD_DIR, "login.html"))

    @app.get("/")
    def root():
        # Serves the dashboard shell. index.html itself redirects to /login
        # before rendering if the browser has no session token.
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))