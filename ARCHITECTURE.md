# Architecture

SmartSIEM is a single FastAPI application wrapping a multi-stage alert pipeline,
a SQLAlchemy data layer, and a WebSocket-driven analyst dashboard.

## Pipeline

Every alert — whether loaded from disk by the demo driver (`run.py`), posted to
the REST API, or received over syslog — flows through the same stages
(`app/services/pipeline.py`):

```
 raw event
    │
    ▼
 validation          app/ingestion/validator.py
    │
    ▼
 normalization       app/normalization/   (field extraction, MITRE ATT&CK
    │                 mapping, attack-type classification)
    ▼
 risk scoring        app/scoring/         (heuristic rules → 0–100 score)
    │
    ├─ ML boost      app/services/ml_engine.py   (Isolation Forest anomaly)
    ├─ Sigma rules   app/detection/sigma/        (YAML detection rules)
    │
    ▼
 response            app/response/        (SOAR playbooks: block IP, notify,
    │                 suppress, escalate — full audit trail)
    ▼
 persistence         raw / normalized / scored / evaluation tables
    │
    ├─ correlation   app/services/correlation_engine.py  (threshold, sequence,
    │                 ioc_plus rules → incidents)
    ├─ UEBA          app/services/ueba_engine.py  (cumulative per-entity risk)
    ├─ attack graph  app/graph/           (entity nodes/edges, lateral-movement
    │                 pattern detection via NetworkX)
    ▼
 broadcast           app/websockets.py → /ws/dashboard (live dashboard feed)
```

## Module map

| Path | Responsibility |
|------|----------------|
| `app/main.py` | App factory, router registration, auth dependency wiring, lifespan (DB init, background tasks, demo pipeline) |
| `app/config.py` | `pydantic-settings` configuration, loaded from environment / `.env` |
| `app/database.py` | Engine, session factory, `get_db` dependency |
| `app/models/` | SQLAlchemy models (~30 tables) + Pydantic schemas |
| `app/migrations.py` | Lightweight versioned migrations applied at startup |
| `app/api/` | One router module per domain (alerts, incidents, playbooks, ML, MITRE, IOC, auth, …) |
| `app/api/deps.py` | Auth dependencies: session cookie or `X-API-Key`, role guard |
| `app/services/` | Business logic (pipeline, ML, UEBA, correlation, threat feeds, sessions, AI) |
| `app/ingestion/` | Loaders, validation, sample generator, syslog/CEF listener |
| `app/normalization/` | Event parsing and enrichment |
| `app/scoring/` | Heuristic risk scoring engine |
| `app/detection/sigma/` | Sigma rule parser and evaluator |
| `app/response/` | SOAR responder, playbook execution, notifications |
| `app/graph/` | Attack graph extraction and path detection |
| `app/templates/` + `app/static/` | Dashboard (vanilla JS + Chart.js / Leaflet / Cytoscape) |
| `run.py` | Demo driver: streams `data/raw_alerts/` through the pipeline |
| `rules/sigma/` | Bundled Sigma detection rules |

## Data layer

SQLite by default (`DATABASE_URL` accepts any SQLAlchemy URL). Core tables:

- **Alert chain**: `raw_alerts` → `normalized_alerts` → `scored_alerts` → `evaluation_results`
- **Response**: `blocked_ips`, `playbooks`, `playbook_executions`, `suppressed_alerts`, `suppression_rules`
- **Investigation**: `incidents`, `incident_timeline`, `incident_comments`, `incident_evidence`, `alert_groups`
- **Detection**: `correlation_rules`, `sigma_rules`, `sigma_matches`, `ioc`, `threat_feed_state`
- **Analytics**: `ip_entity_profiles` (UEBA), `graph_nodes`/`graph_edges`, `lateral_movement_incidents`, `ml_model_meta`, `false_positives`
- **Platform**: `users`, `sessions`, `api_keys`, `audit_log`, `geoip_cache`, `schema_migrations`

## Demo mode

`DEMO_MODE=1` (default) makes opening `/dashboard` wipe alert tables and re-run
the pipeline so alerts stream in one-by-one over WebSocket — great for demos,
destructive for real data. Set `DEMO_MODE=0` anywhere you care about the data.
`AUTO_PIPELINE=1` starts the demo driver as a subprocess on boot.
