# 🛡️ SmartSIEM Risk Engine
### Enterprise-Grade Security Information & Event Management Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.135+-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/scikit--learn-ML%20Engine-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-E63946?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Claude%20AI-Integrated-7C3AED?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge"/>
</p>

<p align="center">
  <strong>A full-stack, production-inspired SIEM + SOAR platform built from scratch.</strong><br/>
  Ingests raw security events → normalizes → scores risk → triggers automated responses → streams everything to a live analyst dashboard.
</p>

---

## 📌 Overview

Modern Security Operations Centers (SOCs) are overwhelmed with alert fatigue — thousands of raw log events per day with no intelligent triage. Commercial tools like Splunk and IBM QRadar solve this at the cost of massive licensing fees and black-box logic.

**SmartSIEM** is an open, transparent, and fully-featured alternative built to demonstrate the complete engineering behind a production SIEM:

- **Ingestion** — Accept raw, unstructured log events via REST API
- **Normalization** — Parse, classify, and enrich events with MITRE ATT&CK mappings, GeoIP, and attack type classification
- **Risk Scoring** — Multi-factor heuristic engine backed by a trained Isolation Forest ML model
- **Automated Response** — SOAR playbook engine that blocks IPs, suppresses duplicates, and fires Slack alerts
- **UEBA** — Tracks entity behavior over time to detect slow-burn attackers that evade threshold-based rules
- **AI-Assisted Analysis** — Claude AI generates natural-language incident summaries, attack explanations, and threat forecast narratives
- **Live Dashboard** — 17-tab professional analyst interface with WebSocket streaming, MITRE coverage matrix, threat forecasting, and ML insights

This is not a toy — it reflects how real threat detection pipelines are engineered.

---

## ✨ What's New (v3.2)

- **🧾 Sigma Detection Rules** — industry-standard YAML detection rules evaluated against every event; 12 curated rules bundled, upload/toggle/dry-run via `/api/v1/sigma/*`; matches boost risk scores by rule level
- **🛰️ Syslog + CEF Ingestion** — asyncio UDP/TCP listener (RFC 3164 / RFC 5424 / ArcSight CEF) feeding the same pipeline as the demo driver, so real devices stream straight into the dashboard (`SYSLOG_ENABLED=1`)
- **🌐 Live Threat-Intel Feeds** — AbuseIPDB blacklist + AlienVault OTX pulse sync into the IOC store on a schedule; feed hits raise alert risk scores (`/api/v1/intel/*`)
- **🔗 Correlation Engine v2** — threshold (N events / entity / window), sequence (recon → exfiltration), and IOC-composite rule types; repeat matches append to the open incident instead of duplicating
- **📁 Case Management** — incident comments, evidence attachments (alerts / IOCs / notes), actor-attributed timeline, and a full case view in the incident drawer
- **🔒 Security Hardening** — DB-backed sessions, no default credentials, global auth on every API route (session cookie or `X-API-Key`), role-gated admin surfaces, CORS + security headers, env-driven config
- **🧪 Engineering** — 117-test pytest suite, Ruff linting, Docker + docker-compose, Makefile, pre-commit hooks, GitHub Actions CI, static-asset dashboard with SRI-pinned CDN dependencies

---

## ✨ What's New (v3.1)

- **🤖 AI Investigator Chat** — Floating chat panel that answers analyst questions grounded in live SIEM data via Claude (`POST /api/ai/chat`)
- **🔎 Pivot Search** — Click any IP or alert ID to see every related artifact in one modal: alerts, incidents, IOC hits, block history, UEBA profile, attack breakdown (`GET /api/v1/pivot/{type}/{value}`)
- **⚡ Quick-Action Toolbar** — Each alert row exposes one-click 🚫 Block IP, 🎯 Add to IOC, 🚨 Create Incident, and FP buttons
- **🗺️ Geo Threat Map** — World map of attacker source IPs with country aggregation, served from `/api/v1/network/geoip`
- **🔥 MITRE ATT&CK Heatmap** — Tactic-grouped technique frequency view with intensity-shaded cells (`GET /api/v1/mitre/heatmap`)
- **⏱️ SLA Tracking** — Per-incident time-to-resolve badges (Critical 1h · High 4h · Medium 24h · Low 72h) with ok/warning/breached states
- **📦 Bulk Incident Ops** — Select-all checkbox + "Close Selected" for incident triage at scale
- **📄 Downloadable Incident Reports** — Per-incident HTML report with built-in Print/Save-as-PDF (`GET /api/v1/incidents/{id}/report`)
- **🔁 Replay-on-Refresh** — Refreshing `/dashboard` resets state and re-runs the pipeline so alerts stream in one-by-one (great for demos; disable with `?replay=0`)
- **🎬 Auto-start Pipeline** — `uvicorn app.main:app` now spawns the alert pipeline as a background subprocess on boot (disable with `AUTO_PIPELINE=0`)

---

## 🎯 Core Capabilities

### 🔍 Threat Detection & Risk Scoring
- **Multi-layer scoring engine** — combines raw severity, MITRE ATT&CK tactic weights, historical entity behavior, IOC feed matches, and geolocation risk into a composite 0–100 risk score
- **MITRE ATT&CK alignment** — every alert is mapped to one or more ATT&CK technique IDs (T1059, T1110, T1566, etc.) covering all 11 tactic categories
- **Attack type classification** — ML-assisted classifier assigns semantic labels (Brute Force, Lateral Movement, Data Exfiltration, Command & Control, etc.) to raw events
- **Custom detection rules** — SOC analysts write JSON-based rules in the dashboard UI, no code required; rules evaluated at ingestion time against every alert

### 🤖 Machine Learning Engine
- **Isolation Forest anomaly detection** — trained on historical alert feature vectors (severity, MITRE density, base risk score) to flag statistical outliers in real time
- **FP-feedback-driven retraining** — analysts mark false positives directly in the UI; the retrain endpoint filters FP alert IDs from the training set and adjusts `contamination` dynamically (`fp_rate × 0.5 + 0.005`) before re-fitting the model
- **Behavior clustering** — groups similar alerts into campaigns/episodes to surface coordinated activity rather than isolated events
- **Anomaly scoring** — `decision_function` output is normalized to a 0–1 confidence score via sigmoid; exposed per-alert alongside binary anomaly flag
- **Model persistence** — trained model serialized via `joblib` to `data/iforest_model.pkl`; `data/ml_meta.json` tracks training samples, contamination value, FP count, and last retrain timestamp
- **7-day threat forecasting** — pure-Python linear regression on 30-day daily alert volumes produces slope, R² confidence, per-day predicted counts, and proportional attack-type breakdown

### 🧑‍💻 User Entity Behavior Analytics (UEBA)
- Every source IP accumulates a **cumulative lifetime risk score** across all alerts it has ever generated — no single-alert threshold needed
- Risk level bands: `Low → Medium → High → Critical` with automatic escalation
- Detects **"Low and Slow"** adversaries: attackers who stay below per-alert thresholds but accumulate anomalous behavior over days or weeks
- Autonomous UEBA incident reports auto-generated when an entity crosses the Critical threshold

### 🎭 SOAR Playbook Engine
- Define automated response playbooks via JSON config: trigger conditions (`risk > 80`, `attack_type = "Brute Force"`, `is_anomaly = true`) map to action types (`block_ip`, `send_slack`, `create_incident`, `suppress_alert`)
- Full execution audit log — every playbook fire is recorded in `PlaybookExecutionDB` with action type, target, success/failure, and timestamp
- Active/inactive toggle per playbook from the dashboard — no restart required
- Execution history chart shows 7-day trigger volume per playbook

### 🌐 Network Intelligence
- **Subnet behavior analysis** — groups `IPEntityProfileDB` records by `/24` subnet, aggregates alert count, cumulative UEBA score, and unique IPs per segment; surfaces top 10 most suspicious network segments
- **Synthetic IP reputation scoring** — zero external API calls; combines IOC feed matches (score 75–88), BlockedIP list (score 72), and UEBA risk level (Critical → 90, High → 68, Medium → 42) into a clean 0–100 label: `Clean / Watchlist / Suspicious / Blocked / Malicious`
- **MITRE ATT&CK coverage matrix** — live 11-column grid showing which techniques have been seen (`covered`), actively firing (`active`), or not yet observed (`unseen`) based on real alert data

### 🛡️ IOC & Threat Intelligence
- Internal **IOC feed manager** — add, activate/deactivate, and search Indicators of Compromise by type (`ip`, `domain`, `hash`, `url`) and severity
- IOC matches evaluated at alert processing time — matched alerts get an automatic risk boost and `Malicious` reputation label
- Supports bulk IOC ingestion via CSV upload

### 🔇 Alert Suppression & Deduplication
- Define suppression rules (by source IP, attack type, or alert signature) to silence known-benign noise without deleting records
- Hash-based deduplication prevents identical alerts from flooding the incident queue
- Suppression rules managed from dashboard with enable/disable toggle and expiry support

### 📋 Compliance Reporting
- Built-in compliance mapping for **NIST CSF**, **ISO 27001**, and **PCI-DSS** control frameworks
- Automated gap analysis based on observed ATT&CK technique coverage
- Exportable PDF compliance reports formatted for C-suite presentation

### 🤖 Claude AI Integration
- **Incident summarization** — Claude generates natural-language narratives for each incident: what happened, what it means, suggested response steps
- **Attack explanation** — ask Claude to explain any alert in plain English for junior analysts
- **Threat forecast narrative** — Claude writes a paragraph-length forecast interpretation combining ML trend data with contextual threat intelligence
- All AI calls are async and non-blocking; responses cached per incident

### 🔔 Real-Time Operations
- **WebSocket streaming** — dashboard subscribes to `/ws/dashboard`; every processed alert is pushed live without polling
- **Velocity ticker** — displays current alert ingestion rate (alerts/minute) with trend arrow
- **Toast notification system** — slide-in notifications replace all `alert()` dialogs for a professional UX
- **Risk trend banner** — auto-appears above the dashboard when the 7-day forecast shows an upward trend (`slope > 2`)

### 🔐 Authentication & Audit
- HTTPOnly cookie-based session authentication with role-based access control
- Full audit log — every analyst action (login, rule change, IP block, playbook toggle, retrain) is recorded with actor, action, target, and timestamp
- Audit log is queryable and exportable from the dashboard

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            SmartSIEM Risk Engine                                │
│                                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────────────────────┐  │
│  │  Log Sources  │    │                  Processing Pipeline                │  │
│  │              │    │                                                      │  │
│  │  • REST API  │───▶│  Ingestion ──▶ Normalization ──▶ Scoring ──▶ SOAR  │  │
│  │  • run.py    │    │    Layer           Layer           Layer      Layer  │  │
│  │    simulator │    │  (validator)   (extractors,    (scorer,     (rules, │  │
│  │  • Webhook   │    │               transformers,   ml_engine,   playbooks│  │
│  │              │    │                mapper,        ueba_engine) blocklist)│  │
│  └──────────────┘    │               attack_type_                          │  │
│                      │               classifier)                           │  │
│                      └──────────────────────────┬───────────────────────────┘  │
│                                                 │                               │
│                                                 ▼                               │
│                      ┌──────────────────────────────────────────────────────┐  │
│                      │                   SQLite Database                    │  │
│                      │  raw_alerts │ normalized_alerts │ scored_alerts      │  │
│                      │  incidents  │ playbooks         │ playbook_executions │  │
│                      │  ioc_feeds  │ blocked_ips       │ suppression_rules  │  │
│                      │  audit_log  │ ueba_profiles     │ false_positives    │  │
│                      │  ml_model_meta                  │ compliance_maps    │  │
│                      └──────────────────────┬───────────────────────────────┘  │
│                                             │                                   │
│                                             ▼                                   │
│                      ┌──────────────────────────────────────────────────────┐  │
│                      │              FastAPI Backend (23 Routers)            │  │
│                      │  /api/alerts  /api/ml  /api/forecast  /api/playbooks │  │
│                      │  /api/ueba    /api/ioc  /api/network  /api/incidents  │  │
│                      │  /api/rules   /api/ai   /api/compliance /api/audit   │  │
│                      │  /api/mitre   /api/pivot /api/metrics  /api/export   │  │
│                      │  /api/webhook /ws/dashboard                          │  │
│                      └──────────────────────┬───────────────────────────────┘  │
│                                             │                                   │
│                                             ▼                                   │
│                      ┌──────────────────────────────────────────────────────┐  │
│                      │         Live Operations Dashboard (17 Tabs)          │  │
│                      │  Dashboard │ Alerts │ Incidents │ Threat Hunt        │  │
│                      │  UEBA      │ Rules  │ IOC       │ Compliance         │  │
│                      │  Audit     │ Geo Map│ Playbooks │ ML Insights        │  │
│                      │  Network Intelligence │ Threat Forecast              │  │
│                      │  MITRE Heatmap        │ Geo Threat Map               │  │
│                      └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Threat Detection Logic

### Stage 1 — Ingestion & Validation
Raw events arrive at `POST /api/v1/alerts/ingest` as JSON payloads. The validator (`ingestion/validator.py`) checks required fields, sanitizes input, and rejects malformed events before they touch the pipeline.

### Stage 2 — Normalization
The normalization layer (`normalization/`) performs four operations in sequence:
1. **Extraction** — pulls source/destination IPs, ports, timestamps, raw severity, usernames, and event signatures from the raw payload
2. **Transformation** — standardizes timestamp formats, maps raw severity strings to numeric 0–10 scale, resolves internal RFC-1918 IPs as "internal"
3. **MITRE Mapping** — regex + keyword patterns match alert content to ATT&CK technique IDs; multi-technique events get multiple IDs
4. **Attack Type Classification** — ML-assisted classifier assigns a semantic label (11 categories) used for playbook routing and forecast breakdown

### Stage 3 — Risk Scoring
The scoring engine (`scoring/scorer.py`) builds a composite risk score from:

| Component | Weight | Description |
|-----------|--------|-------------|
| Base Severity | 30% | Raw severity normalized to 0–100 |
| MITRE Density | 20% | Number of matched ATT&CK techniques × tactic weight |
| Historical Entity Risk | 20% | UEBA cumulative score for source IP |
| IOC Match | 15% | Presence in active IOC feed |
| Geo Risk | 10% | Country-based risk multiplier |
| ML Anomaly Boost | 5% | Isolation Forest anomaly flag adds fixed boost |

### Stage 4 — Automated Response
The SOAR engine (`response/`) evaluates active playbooks against each scored alert. Matching playbooks fire their configured actions:
- `block_ip` → writes to `BlockedIPDB`, adds to runtime blocklist
- `send_slack` → async Slack webhook POST
- `create_incident` → opens a new incident record with auto-generated severity
- `suppress_alert` → adds suppression rule, silences future duplicates

Every action is recorded in `PlaybookExecutionDB` regardless of success or failure.

### Stage 5 — ML Anomaly Detection
After scoring, the `MLEngine.predict_anomaly_with_score()` method runs the alert's feature vector `[severity, mitre_count, base_risk]` through the trained Isolation Forest. A `decision_function` score is normalized to 0–1 via sigmoid: `1 / (1 + e^(raw × 3))`. Alerts with `prediction == -1` are flagged `is_anomaly = True` in `ScoredAlertDB`.

---

## 📊 Dashboard & UI

The operations dashboard is a single-page application served at `/dashboard` with 17 analyst tabs, a command bar, and real-time WebSocket streaming. No framework dependencies — pure HTML5, CSS custom properties, and Vanilla JS.

### Tabs at a Glance

| Tab | Purpose |
|-----|---------|
| **Dashboard** | KPI command center — threat gauge, anomaly sparkline, playbook mini-feed, IP reputation quick-lookup, alert velocity ticker |
| **Live Alerts** | Full alert table with pagination, severity filter, MITRE tag filter, global search, FP marking |
| **Incidents** | Incident lifecycle management — open/investigate/close, severity assignment, Claude AI summary |
| **Threat Hunt** | KQL-like query console (`mitre:T1110 risk:>80 src:192.168.1.0/24`), timeline histogram |
| **UEBA** | Entity risk leaderboard, cumulative score timeline, behavioral spike chart |
| **Detection Rules** | JSON rule builder, rule table with enable/disable toggle |
| **IOC Manager** | IOC feed table, add/deactivate IOCs, bulk CSV import, type/severity filter |
| **Compliance** | NIST/ISO/PCI-DSS control coverage heatmap, gap analysis, PDF export |
| **Audit Log** | Immutable analyst action history, filterable by actor/action type |
| **Geo Map** | Leaflet.js world map with alert origin markers, color-coded by risk severity |
| **Attack Graph** | Cytoscape.js topology — adversary IPs mapped against targeted internal infrastructure |
| **Automated Playbooks** | Playbook table (trigger → action → status), execution log feed, 7-day trigger chart |
| **ML Insights** | Anomaly rate trend, feature importance bars, alert cluster cards, FP feedback history, Retrain button |
| **Network Intelligence** | Suspicious /24 subnet table, IP reputation lookup, MITRE ATT&CK coverage matrix |
| **Threat Forecast** | 30-day historical + 7-day predicted chart, attack breakdown bars, Claude AI narrative |
| **MITRE Heatmap** | Tactic-grouped technique frequency grid with intensity-shaded cells |
| **Geo Threat Map** | Leaflet world map of attacker source IPs aggregated by country (live GeoIP lookup) |

### UI Design
- **Dark theme**: Deep navy (`#060b18`) background, indigo sidebar (`#0d1033`), electric blue accents (`#2979ff`), crimson critical (`#e8294a`), violet AI elements (`#7c3aed`)
- **Light theme**: Soft blue-tinted backgrounds; all severity/accent colors identical across themes
- **Command bar**: Global search (press `/`), notification bell, velocity ticker, sidebar collapse toggle (`B`)
- **Keyboard shortcuts**: `A` → Alerts, `I` → Incidents, `H` → Threat Hunt, `M` → ML Insights, `F` → Forecast, `B` → Toggle sidebar
- **Toast notifications**: Slide-in system replacing all browser `alert()` dialogs
- **Skeleton loaders**: Shimmer placeholders during async data fetches

---

## ⚙️ Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| API Framework | FastAPI 0.135+ |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite (swappable to PostgreSQL) |
| ASGI Server | Uvicorn |
| ML Engine | scikit-learn (IsolationForest) |
| Model Serialization | joblib |
| AI Integration | Anthropic Claude API |
| WebSockets | `websockets` library via Starlette |
| Authentication | HTTPOnly cookies + session tokens |
| Data Validation | Pydantic v2 |

### Frontend
| Component | Technology |
|-----------|-----------|
| UI Framework | Vanilla HTML5 + CSS3 + JavaScript |
| Charts | Chart.js (line, bar, doughnut, radar) |
| Map | Leaflet.js |
| Graph | Cytoscape.js |
| Styling | CSS Custom Properties (full dark/light theme) |
| Audio | Web Audio API (sound alerts) |

---

## 📂 Project Structure

```
smart-siem-risk-engine/
│
├── app/
│   ├── main.py                        # FastAPI app entry point, DB init, router registration
│   ├── database.py                    # SQLAlchemy engine + SessionLocal
│   ├── config.py                      # Environment config (API keys, thresholds)
│   ├── constants.py                   # MITRE tactic weights, severity maps, attack categories
│   ├── utils.py                       # Shared helpers (IP validation, timestamp utils)
│   ├── websockets.py                  # WebSocket manager for live dashboard streaming
│   │
│   ├── api/                           # 23 FastAPI route modules
│   │   ├── routes_alerts.py           # Alert ingestion + retrieval
│   │   ├── routes_ai.py               # Claude AI summary + explanation endpoints
│   │   ├── routes_audit.py            # Audit log query
│   │   ├── routes_auth.py             # Login/logout, session management
│   │   ├── routes_compliance.py       # NIST/ISO/PCI compliance gap analysis
│   │   ├── routes_dashboard.py        # Dashboard data aggregation
│   │   ├── routes_export.py           # CSV/JSON export
│   │   ├── routes_forecast.py         # Linear regression 7-day threat forecast
│   │   ├── routes_health.py           # Health check
│   │   ├── routes_incidents.py        # Incident lifecycle CRUD
│   │   ├── routes_ioc.py              # IOC feed management
│   │   ├── routes_metrics.py          # KPI aggregates
│   │   ├── routes_mitre.py            # MITRE ATT&CK heatmap aggregation
│   │   ├── routes_ml.py               # ML stats + FP-driven retrain
│   │   ├── routes_network.py          # Subnet behavior + IP reputation + GeoIP
│   │   ├── routes_pivot.py            # Cross-entity pivot (IP/alert/host)
│   │   ├── routes_playbooks.py        # Playbook CRUD + execution log
│   │   ├── routes_reports.py          # PDF report generation
│   │   ├── routes_reset.py            # Dev: reset database
│   │   ├── routes_rules.py            # Detection rule CRUD
│   │   ├── routes_suppression.py      # Suppression rule management
│   │   ├── routes_ueba.py             # UEBA entity profiles
│   │   └── routes_webhook.py          # Inbound webhook receiver
│   │
│   ├── models/                        # Pydantic schemas + SQLAlchemy ORM models
│   │   ├── db_models.py               # All DB table definitions
│   │   ├── raw_alert.py               # Inbound alert schema
│   │   ├── normalized_alert.py        # Post-normalization schema
│   │   ├── scored_alert.py            # Post-scoring schema
│   │   └── evaluation_result.py       # ML evaluation result schema
│   │
│   ├── normalization/                 # Alert normalization pipeline
│   │   ├── extractors.py              # Field extraction from raw payloads
│   │   ├── transformers.py            # Severity normalization, timestamp parsing
│   │   ├── mapper.py                  # MITRE ATT&CK technique mapping
│   │   └── attack_type_classifier.py  # Semantic attack label assignment
│   │
│   ├── scoring/                       # Multi-factor risk scoring engine
│   │   ├── scorer.py                  # Orchestrates all scoring components
│   │   ├── score_rules.py             # Heuristic rule evaluations
│   │   ├── score_helpers.py           # Utility functions (geo risk, IOC match weight)
│   │   └── ml_model.py                # ML scoring integration wrapper
│   │
│   ├── services/                      # Core business logic services
│   │   ├── pipeline.py                # End-to-end alert processing orchestrator
│   │   ├── ml_engine.py               # IsolationForest train/predict/retrain
│   │   ├── ueba_engine.py             # Entity behavior tracking + risk accumulation
│   │   ├── correlation_engine.py      # Multi-alert correlation into incidents
│   │   ├── incident_service.py        # Incident CRUD + lifecycle management
│   │   ├── ioc_manager.py             # IOC feed CRUD + match evaluation
│   │   ├── alert_deduplicator.py      # Hash-based duplicate suppression
│   │   ├── scoring_service.py         # Scoring pipeline coordinator
│   │   ├── claude_ai_service.py       # Anthropic Claude API integration
│   │   ├── geoip_service.py           # IP → country/risk resolution
│   │   ├── threat_intel.py            # External + internal threat intel aggregation
│   │   ├── slack_notifier.py          # Slack webhook notifications
│   │   ├── audit_logger.py            # Immutable audit trail writer
│   │   ├── auth_service.py            # Session + credential validation
│   │   └── evaluation_service.py      # ML evaluation metrics computation
│   │
│   ├── response/                      # SOAR response engine
│   │   ├── responder.py               # Playbook evaluation + action dispatch
│   │   ├── decision_engine.py         # Trigger condition evaluator
│   │   ├── blocklist_manager.py       # IP block/unblock operations
│   │   └── notifications.py           # Multi-channel alert delivery
│   │
│   ├── ingestion/                     # Raw event intake
│   │   ├── loader.py                  # Batch log loader
│   │   ├── validator.py               # Schema validation + sanitization
│   │   └── sample_generator.py        # Synthetic alert generator for testing
│   │
│   ├── evaluation/                    # ML model evaluation framework
│   │   ├── evaluator.py               # Cross-validation + hold-out evaluation
│   │   ├── metrics.py                 # Precision, recall, F1, AUC
│   │   └── confusion_matrix.py        # TP/FP/TN/FN matrix builder
│   │
│   ├── reporting/                     # Export + report generation
│   │   ├── report_generator.py        # PDF/HTML report assembly
│   │   └── exporters.py               # CSV/JSON data exporters
│   │
│   └── templates/
│       └── dashboard.html             # Full SPA dashboard (17 tabs, ~2200 lines)
│
├── data/
│   ├── iforest_model.pkl              # Serialized trained Isolation Forest model
│   └── ml_meta.json                   # Training metadata (samples, contamination, FP count)
│
├── scripts/                           # Utility scripts
├── tests/                             # Test suite
├── run.py                             # Synthetic attack traffic simulator
├── requirements.txt
└── smart_siem.db                      # SQLite database (auto-created on first run)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- `pip`
- Optional: Anthropic API key (for Claude AI features)
- Optional: Slack webhook URL (for automated Slack notifications)

### 1 — Clone & Install
```bash
git clone https://github.com/svemula17/smart-siem-risk-engine.git
cd smart-siem-risk-engine

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

make install-dev                  # or: pip install -r requirements.txt -r requirements-dev.txt
```

### 2 — Configure (Optional)
```bash
cp .env.example .env
# Set ADMIN_PASSWORD, ANTHROPIC_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, etc.
```
Everything has a safe default — with no `.env` at all, a random admin
password is generated and printed once on first boot.

### 3 — Launch the Platform
```bash
make dev                          # uvicorn app.main:app --reload --port 8000
```

The database is created and migrated automatically on first boot.
Navigate to **http://localhost:8000** and log in as `admin` with your
`ADMIN_PASSWORD` (or the password printed in the console).

### 4 — Simulate Attack Traffic
In a second terminal (with venv activated):
```bash
make demo                         # python run.py
```

This streams the sample events in `data/samples/` (and any alerts under
`data/raw_alerts/`) through the full pipeline — within seconds you will see
UEBA profiles building, Sigma rules matching, incidents being created,
playbooks firing, and the ML model training on the accumulating history.

### Or: run it in Docker
```bash
docker compose up -d              # API on :8000, syslog on 5514/udp + 5515/tcp
```

### Feed it real logs over syslog
```bash
# In .env: SYSLOG_ENABLED=1, then restart. Point any device at udp/5514 or tcp/5515:
echo '<34>Oct 11 22:14:15 web01 sshd[2412]: Failed password for root from 203.0.113.9 port 22 ssh2' | nc -u -w1 localhost 5514
```
RFC 3164, RFC 5424, and ArcSight CEF payloads are parsed, normalized, scored,
and streamed to the dashboard like any other alert.

---

## ▶️ Usage Workflow

### Typical SOC Analyst Workflow

**1. Monitor the Dashboard tab**
- The threat gauge shows current composite risk (0–100)
- The velocity ticker shows alerts/minute in real time
- The risk trend banner warns when the forecast predicts an upward spike

**2. Triage alerts in the Live Alerts tab**
- Filter by severity (`Critical`, `High`, `Medium`, `Low`) or attack type
- Use the global search bar (`/` to focus) for KQL-style queries
- Mark false positives directly from the alert row — this feeds the ML retraining loop

**3. Investigate incidents**
- Incidents are auto-created by the correlation engine for related alert clusters
- Click any incident → request Claude AI summary → get plain-English narrative of what happened and recommended response steps
- Update incident status (Open → Investigating → Closed)

**4. Check UEBA tab**
- Review entity risk leaderboard — any IP in Critical band should be investigated
- Click an entity to see its full alert history and risk accumulation curve

**5. Review Playbook executions**
- Go to Automated Playbooks tab → Execution Log
- Verify that block_ip and create_incident actions fired correctly for high-risk events

**6. Retrain the ML model**
- After accumulating FP feedback from analysts, go to ML Insights tab
- Click **Retrain Model** — the endpoint filters FP alerts from the training set, adjusts contamination, re-fits the Isolation Forest, and updates `data/ml_meta.json`
- The new model is hot-loaded and active immediately

**7. Review the Threat Forecast**
- Threat Forecast tab shows predicted alert volume for the next 7 days
- Claude AI narrative panel interprets the trend in plain language
- Attack type breakdown shows which threat categories to expect most

---

## 🧪 SOC Use Cases

| Scenario | How SmartSIEM Handles It |
|----------|--------------------------|
| **Brute Force campaign** | Multiple failed-auth alerts from one IP → UEBA risk accumulates → Playbook fires `block_ip` + `send_slack` after risk threshold → Incident auto-created |
| **Slow-burn credential stuffing** | Low-frequency logins from one IP over 5 days stay below per-alert rules → UEBA cumulative risk crosses Critical → Autonomous anomaly incident raised |
| **Insider threat / lateral movement** | Internal IP generating T1021 (Remote Services) alerts → DBSCAN clusters it with T1078 (Valid Accounts) alerts → Incident links all events → Claude explains the kill chain |
| **Malicious IP seen in IOC feed** | New alert from IP in IOC DB → Risk score boosted → Reputation label set to Malicious → Analyst sees red reputation badge in Alerts tab |
| **Alert storm / log flooding** | Deduplicator hashes identical events → Suppression rule auto-triggers after N duplicates → Alert queue stays clean |
| **Compliance audit prep** | Compliance tab shows MITRE technique coverage mapped to NIST/ISO controls → Export PDF report for auditors |
| **Threat hunting** | Analyst opens Threat Hunt tab → queries `mitre:T1055 risk:>70 src:10.0.0.0/8` → timeline histogram shows attack window → pivots to incident |

---

## 🔐 Security Considerations

- **Authentication**: HTTPOnly session cookies prevent JavaScript XSS token theft; all dashboard routes require valid session
- **Input Validation**: All ingestion endpoints validate with Pydantic v2 schemas before touching the DB; SQL injection prevented by SQLAlchemy ORM parameterization
- **Audit Trail**: Every privileged action (rule changes, IP blocks, model retrains, logins) is logged immutably in the audit table — cannot be deleted from the UI
- **IOC Data**: IOC feeds are stored locally — no external DNS lookups or third-party API calls at alert processing time (no data leakage)
- **IP Reputation**: Fully local scoring (IOC DB + BlockedIP list + UEBA) — no calls to external reputation APIs that could expose your environment's IP addresses
- **AI Privacy**: Claude AI summaries are opt-in per incident; no alert data is sent to the API unless the analyst explicitly requests a summary
- **Model Security**: Trained model file (`iforest_model.pkl`) should be treated as a sensitive artifact — stored in `data/` which should be excluded from public access in production deployments

---

## 📈 Future Enhancements

| Enhancement | Description |
|-------------|-------------|
| **PostgreSQL support** | Swap SQLite for PostgreSQL via SQLAlchemy engine string — needed for multi-worker production deployments |
| **Kafka ingestion** | Replace REST ingestion with Kafka consumer for high-throughput log streaming (100k+ events/sec) |
| **STIX/TAXII integration** | Pull IOC feeds from TAXII servers (MISP, OpenCTI) in STIX 2.1 format |
| **Active Directory connector** | Ingest Windows Security Event Log via WinRM; enrich alerts with AD user/group context |
| **EDR telemetry integration** | Native connectors for CrowdStrike Falcon, SentinelOne, Carbon Black telemetry |
| **SOAR action expansion** | Add `quarantine_host`, `reset_password`, `disable_account`, `open_ticket` (Jira/ServiceNow) action types |
| **Threat graph enrichment** | Integrate with MISP or VirusTotal API to enrich IOC nodes on the attack graph |
| **Advanced ML models** | Evaluate Autoencoder and LSTM-based sequence anomaly models for time-series behavioral patterns |
| **Multi-tenant support** | Separate data namespaces per organization for MSSP deployments |
| **Sigma rule import** | Parse and ingest Sigma detection rules directly — the community-standard detection format |
| **OpenTelemetry metrics** | Expose Prometheus-compatible metrics (`/metrics`) for Grafana dashboarding of the platform itself |

---

## 🧪 Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run the test suite
pytest tests/ -v

# Test individual endpoint
python test_endpoint.py

# Verify DB integrity
python test_db.py
```

---

## 🤝 Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes — follow the existing module structure (new API features go in `app/api/routes_*.py`, new services in `app/services/`)
4. Test your changes: `pytest tests/`
5. Submit a Pull Request with a clear description of what the change does and why

**Good first issues:**
- Add a new playbook action type
- Add a new MITRE ATT&CK technique mapping in `constants.py`
- Write unit tests for the scoring engine
- Add a new compliance framework (SOC 2, HIPAA)

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Sai Kumar Vemula**

> Built to demonstrate full-stack cybersecurity engineering — from raw log ingestion through ML anomaly detection, automated SOAR response, and AI-assisted analyst workflows. This project reflects real-world SIEM/SOAR architecture at a fraction of the cost of commercial platforms.

<p>
  <a href="https://github.com/svemula17"><img src="https://img.shields.io/badge/GitHub-svemula17-181717?style=for-the-badge&logo=github"/></a>
  &nbsp;
  <a href="https://www.linkedin.com/in/saikumarvemula"><img src="https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin"/></a>
</p>

---

<p align="center">
  <sub>SmartSIEM v3.1.0 — Built from scratch. No black boxes.</sub>
</p>
