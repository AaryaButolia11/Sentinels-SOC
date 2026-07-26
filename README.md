# Sentinel — AI-Powered Behavioral Anomaly Detection

A behavioral (not signature-based) threat detection system for access logs. It
learns what "normal" looks like per user and per device, scores every event for
anomaly risk, classifies the ones that look like attacks, explains _why_ it
flagged them, and streams the results to a live analyst console.

## What's implemented

| Capability                                                             | Where                                         |
| ---------------------------------------------------------------------- | --------------------------------------------- |
| Synthetic log generator (5 attack types + normal traffic)              | `data/generate_logs.py`                       |
| Real-time log streaming (WebSocket replay of a held-out slice)         | `api/main.py` + `api/routes/stream.py`        |
| Behavioral profile engine (online per-user/device baselines)           | `features/user_profiles.py`                   |
| Cold-start handling (Bayesian shrinkage to a population prior)         | `features/cold_start.py`                      |
| Isolation Forest anomaly scoring (stage 1, unsupervised)               | `models/anomaly_model.py`                     |
| Class-imbalance handling (inverse-freq weights + targeted SMOTE)       | `models/imbalance.py`                         |
| Attack classification (stage 2, LightGBM, 5 classes)                   | `models/classifier.py`                        |
| Risk scoring 0-100                                                     | anomaly score x 100, surfaced across API + UI |
| Explainable AI (SHAP -> one-sentence rationale, with z-score fallback) | `models/explainability.py`                    |
| Concept-drift monitoring (rolling + windowed FP-rate)                  | `models/drift_monitor.py`                     |
| **AI Security Copilot** (LLM briefings + MITRE mapping + playbook)     | `api/routes/copilot.py`                       |
| **Interactive investigation page** (per-user baseline inspector)       | `api/routes/investigation.py` + dashboard     |
| **Animated network attack replay** (canvas geo-arc map)                | `dashboard/app.js`                            |
| Analyst dashboard (metrics, live feed, eval, drift)                    | `dashboard/`                                  |

## Architecture: a two-stage detector

```
event -> feature engineering -> [Stage 1] Isolation Forest anomaly score
                                     |
                          score >= threshold?
                                     | yes
                                     v
                        [Stage 2] LightGBM attack classifier -> SHAP explanation -> Alert
```

Stage 1 is unsupervised, so it works from day one and can flag _novel_ patterns
it was never trained on. Stage 2 only runs on already-suspicious events and
answers "which known attack type is this?". This keeps the rare-attack /
dominant-normal imbalance out of the classifier entirely -- "normal" is handled
by the threshold, not a class.

The **ordering rule** matters throughout: features for an event are always
computed _before_ the event is folded into its own baseline, so an event never
"sees itself" and smooths away its own anomaly. `build_feature_table()` and
`Pipeline.process()` both enforce this.

## Project structure

```
sentinel/
|-- api/
|   |-- main.py                 # FastAPI app, lifespan training, WS replay loop
|   |-- state.py                # shared handle to the trained pipeline
|   |-- db/
|   |   |-- init_db.py          # engine / SessionLocal / get_db / init_db
|   |   `-- models.py           # Event, Alert, Feedback tables
|   `-- routes/
|       |-- alerts.py           # GET /alerts, /alerts/{id}
|       |-- feedback.py         # POST /feedback  -> drift monitor
|       |-- stream.py           # WS /ws/alerts
|       |-- users.py            # GET /users
|       |-- copilot.py          # POST /copilot   (AI Security Copilot)
|       `-- investigation.py    # GET /investigate/{user_id}
|-- dashboard/                  # vanilla JS SPA (no build step)
|   `-- index.html, app.js, styles.css
|-- data/                       # generator, schema, sample_logs.csv
|-- features/                   # profiles, cold start, feature engineering
|-- models/                     # anomaly, classifier, imbalance, explainability, drift
|-- streaming/pipeline.py       # per-event orchestration
|-- conftest.py, sitecustomize.py, requirements.txt
`-- tests/
```

## Quick start

```bash
pip install -r requirements.txt

# (Optional) regenerate data -- all 5 attack types, realistically imbalanced
python data/generate_logs.py --users 120 --days 21 \
    --events_per_user_per_day 6 --attack_prob 0.14 --seed 7 \
    --out data/sample_logs.csv

python -m pytest -q                 # 14 tests

python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/
```

On startup the API trains on the first 80% of the log ("historical") and replays
the last 20% as a live WebSocket stream, so the dashboard populates on its own.

### AI Security Copilot

The Copilot turns an alert into an analyst briefing: situation summary, MITRE
ATT&CK technique, severity, a prioritized response playbook, and a hunt pivot.

- **Offline (default):** a per-attack-type playbook grounded in the alert's own
  evidence. No external calls -- works in CI and air-gapped demos.
- **Live LLM:** provide a `GROQ_API_KEY` and the Copilot calls Groq's free
  OpenAI-compatible Chat Completions API with a defensive-SOC prompt built only
  from the structured alert. Any failure falls back to the playbook, and the UI
  labels which path produced the text. Groq's free tier needs no credit card --
  grab a key at [console.groq.com](https://console.groq.com).

Copy `.env.example` to `.env` and drop your key in — the app auto-loads `.env`
on startup, so no extra flags are needed:

```dotenv
GROQ_API_KEY=gsk_your_actual_key_here
# SOC_COPILOT_MODEL=llama-3.3-70b-versatile        # optional (this is the default)
# GROQ_BASE_URL=https://api.groq.com/openai/v1     # optional
```

Verify it loaded by opening `http://127.0.0.1:8000/copilot/health` — you should
see `"llm_available": true`. Because Groq is OpenAI-compatible, pointing
`GROQ_BASE_URL` (and the key/model) at any other OpenAI-style endpoint — a local
Ollama/vLLM server, OpenRouter, etc. — works without code changes.

## A note on evaluation honesty

On the synthetic data the classifier scores near-perfect macro F1. That's
expected and **not** a claim of real-world accuracy: the injected attacks have
deliberately distinct feature signatures, so the supervised stage separates them
easily. The parts that transfer to real data are the _design_ choices -- the
two-stage split, cold-start shrinkage, imbalance handling, the ordering rule,
and drift monitoring -- not the headline number. The more informative signal is
that the **unsupervised** stage alone already separates every attack type's mean
risk (0.45-0.75) from normal traffic (~0.17) with no labels at all.

## Key API endpoints

```
GET  /health                     pipeline readiness
GET  /metrics                    held-out P/R/F1 + live counters
GET  /alerts                     recent alerts (filter by ?user_id=)
POST /feedback                   analyst verdict -> drift status
GET  /feedback/drift-status      current drift signal
GET  /investigate/{user_id}      baseline + alerts + risk timeline
GET  /investigate/users          browsable user list
POST /copilot                    analyst briefing for an alert
GET  /dashboard/attack-replay    geo arcs for the animated map
WS   /ws/alerts                  live alert + heartbeat stream
```
