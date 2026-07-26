# Sentinel AI — Behavioral Anomaly Detection for Cybersecurity

> An AI/ML-powered **behavioral anomaly detection** platform that learns normal user &
> device access patterns and detects cyber threats in real time — instead of relying on
> static signatures. Built for the **Honeywell Campus Connect** project submission.

**Live Prototype:** https://sentinels-soc.onrender.com/
**Repository:** https://github.com/AaryaButolia11/Sentinels-SOC

`UEBA` · `SOC` · `Anomaly Detection` · `MITRE ATT&CK` · `Explainable AI (SHAP)` ·
`Isolation Forest` · `LightGBM` · `Concept-Drift Monitoring` · `Real-Time WebSocket Streaming` · `FastAPI`

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Solution Overview](#2-solution-overview)
3. [Key Features](#3-key-features)
4. [Problem-Statement Coverage](#4-problem-statement-coverage)
5. [Technical Approach](#5-technical-approach)
6. [Project Workflow](#6-project-workflow)
7. [System Design & Architecture](#7-system-design--architecture)
8. [Technology Stack](#8-technology-stack)
9. [API Endpoints](#9-api-endpoints)
10. [Results & Metrics](#10-results--metrics)
11. [Requirements](#11-requirements)
12. [Installation & Steps to Run](#12-installation--steps-to-run)
13. [Using the Dashboard](#13-using-the-dashboard)
14. [Project Structure](#14-project-structure)
15. [Limitations & Notes](#15-limitations--notes)
16. [Future Work](#16-future-work)
17. [Author](#17-author)

---

## 1. Problem Statement

Modern enterprises generate thousands of authentication and access events every minute
across cloud platforms, VPNs, identity providers, and endpoint devices. Traditional
security tools rely on **predefined signatures and static rules**, which makes them
ineffective against evolving threats such as insider attacks, credential misuse, lateral
movement, device spoofing, and zero-day behavior.

Security teams need an intelligent, **behavior-driven** system that learns what "normal"
looks like for each user and device, detects deviations in real time, explains its
reasoning to reduce false positives, and accelerates incident response.

---

## 2. Solution Overview

**Sentinel AI** is a **User & Entity Behavior Analytics (UEBA)** platform. It ingests
access logs, builds a personalized behavioral baseline for every user, and runs a
**two-stage detection pipeline**:

- **Stage 1 — Unsupervised anomaly scoring** (Isolation Forest): assigns every event a
  calibrated `0–1` risk score and can catch novel, never-before-labeled patterns.
- **Stage 2 — Supervised attack classification** (LightGBM): categorizes confirmed
  anomalies into one of five known attack types.

Every alert is then **enriched** with a severity rating, a **MITRE ATT&CK** technique
mapping, a **SHAP-based plain-English explanation**, and a **ranked response playbook**,
before being streamed live to an interactive **SOC dashboard**.

---

## 3. Key Features

- **Behavioral (non-signature) detection** — learns per-user, per-device baselines.
- **16 engineered behavioral features** across temporal, geographical, device,
  credential, and resource-access dimensions.
- **Two-stage AI pipeline** — unsupervised anomaly detection + supervised classification.
- **Five attack types detected** — Credential Misuse, Brute Force, Lateral Movement,
  Impossible Travel, Device Spoofing.
- **Explainable AI (SHAP)** — human-readable reason for every alert.
- **Alert enrichment** — severity scoring, MITRE ATT&CK mapping, recommended actions.
- **Class-imbalance handling** — inverse-frequency class weighting + SMOTE.
- **Concept-drift monitoring** — rolling + windowed (ADWIN-style) drift detection with a
  live "retraining recommended" signal.
- **Cold-start handling** — per-feature Bayesian shrinkage blends user history with a
  population prior.
- **Real-time streaming** — WebSocket alert broadcast + stateful replay engine.
- **Interactive SOC dashboard** — live metrics, threat map, alert feed, risk radar,
  investigation view, and an analyst feedback loop.
- **Synthetic data generator** — configurable enterprise logs with injected labeled attacks.

---

## 4. Problem-Statement Coverage

| Requirement | Status | Implementation |
|---|:---:|---|
| AI/ML behavioral detection (not signature-based) | ✅ | Isolation Forest + LightGBM over per-user baselines |
| Generate synthetic access logs | ✅ | `data/generate_logs.py` attack-injection engine |
| Detect credential misuse | ✅ | Classifier → MITRE T1078 |
| Detect brute-force attacks | ✅ | Classifier → MITRE T1110 |
| Detect lateral movement | ✅ | Classifier → MITRE T1021 |
| Detect impossible travel | ✅ | Geo-velocity feature + classifier |
| Detect device spoofing | ✅ | New-device features + classifier → MITRE T1036 |
| Address class imbalance | ✅ | `models/imbalance.py` (class weighting + SMOTE) |
| Address concept drift | ✅ | `models/drift_monitor.py` (rolling + windowed) |
| Address cold-start | ✅ | `features/cold_start.py` (Bayesian shrinkage) |
| Classify attack types | ✅ | LightGBM, 5 classes |
| Explainable risk scores | ✅ | `models/explainability.py` (SHAP + fallback) |
| Analyst dashboard | ✅ | `dashboard/` SOC console + investigation view |
| Detection accuracy / low FP / classification / design | ✅ | ROC-AUC 0.9855, low FP rate, 100% macro classification |

---

## 5. Technical Approach

### Behavioral Feature Engineering
16 features are computed **per event, before** that event is folded into the user's
baseline — preventing an event from "seeing itself" (no data leakage). Dimensions:

- **Temporal:** hour of day, hour typicality, seconds since last event
- **Geographical:** distance from home (km), geo-velocity (km/h — impossible-travel
  signal), new-country flag
- **Device:** is-new-device flag, device familiarity
- **Credential / Auth:** auth-failed flag, failed attempts in last 5 min,
  privilege-escalation action flag
- **Resource / Behavior:** resource sensitivity, resource familiarity, session duration,
  session-duration deviation, baseline confidence

### Two-Stage Detection
- **Stage 1 (unsupervised):** Isolation Forest, StandardScaler-normalized, calibrated to a
  stable `0–1` risk range. Designed as an **extensible ensemble** (a reconstruction-error
  autoencoder path is included behind the same interface for future expansion).
- **Stage 2 (supervised):** LightGBM (with a scikit-learn Gradient Boosting fallback),
  runs only on flagged events, emitting a predicted attack label + confidence.

### Robustness Concerns
- **Class imbalance:** inverse-frequency class weighting (always on) + SMOTE oversampling
  on the training split only.
- **Cold-start:** per-feature Bayesian shrinkage / credibility weighting.
- **Concept drift:** rolling false-positive rate + ADWIN-style windowed comparison; raises
  a retraining recommendation when drift is detected.

### Explainability & Enrichment
- **SHAP** TreeExplainer over the classifier, with a z-score-style fallback for novel
  anomalies — both produce a short, analyst-readable sentence.
- **Enrichment:** severity (risk × asset sensitivity), MITRE ATT&CK technique/tactic, and
  a ranked response playbook (e.g., Block IP, Require MFA, Isolate host).

---

## 6. Project Workflow

1. **Data Ingestion** — collect access events (timestamp, user, device, IP, geo, resource,
   auth result); synthetic logs generated by `generate_logs.py`.
2. **Parsing & Preprocessing** — type-clean events and stream them in strict time order.
3. **Feature Engineering** — compute 16 behavioral features per event (before baseline update).
4. **Baseline / Profile Building** — update each user's rolling behavioral profile.
5. **Cold-Start Blending** — blend thin user history with a population prior via Bayesian shrinkage.
6. **Stage 1 — Anomaly Scoring** — Isolation Forest assigns a calibrated `0–1` risk score.
7. **Stage 2 — Attack Classification** — LightGBM labels suspicious events as one of five attack types.
8. **Explainability (SHAP)** — generate a plain-English reason + top contributing features.
9. **Alert Enrichment** — attach severity, MITRE ATT&CK mapping, and recommended actions.
10. **Persistence & Streaming** — store in SQLite; broadcast the alert over WebSocket in real time.
11. **SOC Dashboard** — analysts monitor live metrics, threat map, alert feed, and investigation view.
12. **Feedback & Drift Monitoring** — analyst verdicts feed the drift monitor, closing the learning loop.

*(Steps 1–5 are shared by training and live scoring; 6–9 are the detection core; 10–12 are the real-time & feedback layer.)*

---

## 7. System Design & Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                     SENTINEL AI PIPELINE                   │
                    └──────────────────────────────────────────────────────────┘

  Access Logs ──▶ Feature Engineering ──▶ Stage 1: Anomaly Scoring (Isolation Forest)
 (synthetic /        (16 features,               │  risk score 0–1
  real)              cold-start blended)         ▼
                                          suspicious?  ──no──▶ (routine, not alerted)
                                                │ yes
                                                ▼
                                   Stage 2: Attack Classification (LightGBM)
                                                │  predicted type + confidence
                                                ▼
                                   Explainability (SHAP) + Enrichment
                                   (severity · MITRE ATT&CK · response playbook)
                                                │
                          ┌─────────────────────┼─────────────────────┐
                          ▼                     ▼                     ▼
                   SQLite (persist)     WebSocket broadcast     Drift Monitor
                                                │                     ▲
                                                ▼                     │ analyst verdicts
                                        SOC Dashboard ────────────────┘
                                 (metrics · threat map · feed · radar ·
                                  investigation view · feedback loop)
```

A single `Pipeline.process(event)` call powers **both** batch training and live scoring,
so the FastAPI backend and the replay simulator share identical logic.

---

## 8. Technology Stack

| Layer | Technologies |
|---|---|
| Languages | Python (backend & ML), JavaScript (dashboard) |
| Backend & API | FastAPI, REST endpoints, WebSocket streaming, Pydantic schemas |
| Machine Learning | scikit-learn, Isolation Forest, LightGBM, SHAP, SMOTE (imbalanced-learn) |
| Data | Pandas, NumPy |
| Persistence | SQLite via SQLAlchemy (Events, Alerts, Feedback) |
| Frontend | Single-page SOC console — vanilla JavaScript + Chart.js, live WebSocket updates |
| Server | Uvicorn (ASGI); hosted prototype on Render |

---

## 9. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/admin/login` | Admin login; clears tables and starts the live replay |
| `POST` | `/replay/start` | Manually (re)start the pre-scored replay stream |
| `GET`  | `/replay/status` | Current replay progress/stats |
| `GET`  | `/health` | Liveness + pipeline-ready check |
| `GET`  | `/metrics` | Model readiness, per-class scores, alert rate, FP rate, AI confidence |
| `GET`  | `/alerts` | List recent alerts (optional `user_id` filter) |
| `GET`  | `/alerts/{alert_id}` | Full alert detail incl. explanation + linked event |
| `POST` | `/feedback` | Submit analyst verdict (`confirmed` / `false_positive`) |
| `GET`  | `/feedback/drift-status` | Current drift status + retraining recommendation |
| `WS`   | `/ws/alerts` | WebSocket stream of new alerts as they are raised |
| `GET`  | `/users` | List users |
| `GET`  | `/dashboard/overview` | Timeline, threat map nodes, risk radar, classification, alerts |
| `GET`  | `/dashboard/trend` | Rolling risk-trend points |
| `GET`  | `/dashboard/attack-replay` | Geo attack arcs for the threat map |

---

## 10. Results & Metrics

Evaluated on a synthetic enterprise dataset of **20,351 events** (19,200 normal + 1,151
labeled attacks across five categories).

### Stage 1 — Behavioral Anomaly Detection
| Metric | Value |
|---|:---:|
| ROC-AUC | **0.9855** |
| Precision | **87.1%** |
| Recall | **76.3%** |
| F1-Score | **81.3%** |

Confusion matrix — TN: 19,070 · FP: 130 · FN: 273 · TP: 878 (low false-positive rate).

### Stage 2 — Attack Classification
| Metric | Value |
|---|:---:|
| Macro Precision | **100%** |
| Macro Recall | **100%** |
| Macro F1-Score | **100%** |

### End-to-End Replay (4,071 events replayed as a live stream)
| Attack Type | Detected / Total | Rate |
|---|:---:|:---:|
| Brute Force | 128 / 128 | 100% |
| Credential Misuse | 9 / 9 | 100% |
| Device Spoofing | 6 / 6 | 100% |
| Impossible Travel | 8 / 16 | 50% |
| Lateral Movement | 15 / 72 | 20.8% |
| **Overall end-to-end recall** | **166 / 231** | **71.9%** |

> **Note:** All metrics are on a synthetically generated dataset with injected attacks.
> They validate the correctness and effectiveness of the architecture and are not
> production-level results on real-world traffic.

---

## 11. Requirements

- **Python 3.10+**
- Core dependencies (see `requirements.txt`):
  - `fastapi`, `uvicorn[standard]`, `websockets`
  - `sqlalchemy`, `pydantic`
  - `scikit-learn`, `pandas`, `numpy`, `lightgbm`, `imbalanced-learn`, `shap`
  - `Faker` (dataset generation), `pytest`, `httpx` (tests)

---

## 12. Installation & Steps to Run

```bash
# 1. Clone the repository
git clone https://github.com/AaryaButolia11/Sentinels-SOC.git
cd Sentinels-SOC

# 2. (Recommended) create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate synthetic access logs
python data/generate_logs.py --users 60 --days 14 \
       --events_per_user_per_day 8 --out data/sample_logs.csv

# 5. (Optional) run the test suite
python -m pytest -q

# 6. Start the API + dashboard server
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000

# 7. Open the dashboard in your browser
#    http://127.0.0.1:8000/
```

**Data generator options** (`data/generate_logs.py`):

| Flag | Default | Description |
|---|:---:|---|
| `--users` | 60 | Number of simulated users |
| `--days` | 14 | Days of activity to simulate |
| `--events_per_user_per_day` | 8 | Average events per user per day |
| `--attack_prob` | 0.03 | Probability of injecting an attack |
| `--seed` | 42 | Random seed for reproducibility |
| `--out` | `sample_logs.csv` | Output CSV path |

---

## 13. Using the Dashboard

1. Open **http://127.0.0.1:8000/** (or the live URL).
2. Sign in with the **demo admin credentials**:
   - **Username:** `admin`
   - **Password:** `admin123`
3. Logging in clears the tables and streams the pre-scored held-out events as a
   **simulated live feed**. Alerts, the threat map, and charts populate within seconds.
4. Explore: live metrics strip, geographical threat map, live alert feed (with severity,
   MITRE technique, explanation, recommended actions), risk radar, risk-trend and
   severity-mix charts, and the **investigation view** for per-user drill-down.
5. Mark alerts **confirmed** or **false-positive** — verdicts feed the drift monitor and
   can trigger a "retraining recommended" banner.

---

## 14. Project Structure

```text
Sentinels-SOC/
├── api/
│   ├── main.py                 # FastAPI entrypoint: train, replay, endpoints
│   ├── db/
│   │   ├── init_db.py
│   │   └── models.py           # SQLAlchemy models: Event, Alert, Feedback
│   └── routes/
│       ├── alerts.py           # GET /alerts, /alerts/{id}
│       ├── feedback.py         # POST /feedback, GET /feedback/drift-status
│       ├── stream.py           # WS /ws/alerts
│       └── users.py            # GET /users
├── dashboard/
│   ├── index.html              # SOC console (vanilla JS + Chart.js)
│   ├── app.js
│   └── styles.css
├── data/
│   ├── generate_logs.py        # Synthetic log + attack-injection engine
│   ├── schemas.py
│   └── sample_logs.csv
├── features/
│   ├── feature_engineering.py  # 16 behavioral features
│   ├── user_profiles.py        # Rolling per-user baselines
│   └── cold_start.py           # Bayesian-shrinkage cold-start blending
├── models/
│   ├── anomaly_model.py        # Stage 1: Isolation Forest scorer
│   ├── classifier.py           # Stage 2: LightGBM attack classifier
│   ├── imbalance.py            # Class weighting + SMOTE
│   ├── explainability.py       # SHAP + fallback explanations
│   ├── drift_monitor.py        # Concept-drift detection
│   └── enrichment.py           # Severity + MITRE ATT&CK + response playbooks
├── streaming/
│   └── pipeline.py             # Orchestrates the full per-event flow
├── requirements.txt
└── tests/
```

---

## 15. Limitations & Notes

- **Real-time** is demonstrated via a **stateful replay** of held-out data (a simulated
  live stream with correct time-ordered, no-look-ahead scoring) — not production traffic.
- **Metrics** are computed on a **synthetic** dataset with injected attacks; treat them as
  architecture validation, not real-world performance.
- **Scalability** is prototype-level: SQLite persistence and a single-process WebSocket
  pub/sub (swap for Postgres/Redis for multi-worker deployments).
- **Anomaly stage** currently runs **Isolation Forest**; the module is structured as an
  extensible ensemble (an autoencoder path is included but disabled by default).
- The system uses **16 behavioral features** (defined in `feature_engineering.py`).

---

## 16. Future Work

- Ingest **real enterprise logs** from identity providers, VPNs, cloud, and SIEM/SOAR.
- Enable the **autoencoder ensemble** path and add more unsupervised detectors.
- Improve detection of subtle attacks (e.g., **lateral movement**) with sequence models.
- Production hardening: Postgres/Redis, containerized deployment, role-based access.
- Automated **retraining pipeline** triggered by drift signals.

---

## 17. Author

**Aarya Butolia**
Honeywell Campus Connect — Candidate ID 20509197
Email: aaryabutolia@gmail.com

- Live Prototype: https://sentinels-soc.onrender.com/
- GitHub: https://github.com/AaryaButolia11/Sentinels-SOC