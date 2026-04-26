import os
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import text

from app.api.routes_alerts import router as alerts_router
from app.api.routes_ai import router as ai_router
from app.api.routes_audit import router as audit_router
from app.api.routes_compliance import router as compliance_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_export import router as export_router
from app.api.routes_health import router as health_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ioc import router as ioc_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_reports import router as reports_router
from app.api.routes_reset import router as reset_router
from app.api.routes_rules import router as rules_router
from app.api.routes_auth import router as auth_router
from app.api.routes_suppression import router as suppression_router
from app.api.routes_ueba import router as ueba_router
from app.api.routes_webhook import router as webhook_router
from app.api.routes_ml import router as ml_router
from app.api.routes_forecast import router as forecast_router
from app.api.routes_playbooks import router as playbooks_router
from app.api.routes_network import router as network_router
from app.api.routes_mitre import router as mitre_router
from app.api.routes_pivot import router as pivot_router

from app.database import Base, engine

app = FastAPI(title="Smart SIEM Risk Engine API", version="3.0.0")


def init_db() -> None:
    # Create all new tables (idempotent)
    Base.metadata.create_all(bind=engine)

    # Safe column migrations for existing tables
    migrations = [
        "ALTER TABLE normalized_alerts ADD COLUMN attack_type VARCHAR DEFAULT 'Unknown Threat'",
        "ALTER TABLE scored_alerts ADD COLUMN is_anomaly BOOLEAN DEFAULT 0",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                pass  # Column/table already exists


init_db()

from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard")

# Core
app.include_router(health_router,      tags=["Health"])
app.include_router(auth_router,        tags=["Authentication"])
app.include_router(alerts_router,      tags=["Alerts"])
app.include_router(metrics_router,     tags=["Metrics"])
app.include_router(reports_router,     tags=["Reports"])
app.include_router(dashboard_router,   tags=["Dashboard"])
app.include_router(reset_router,       tags=["Reset"])
app.include_router(incidents_router,   tags=["Incidents"])
app.include_router(rules_router,       tags=["Rules"])
app.include_router(ueba_router,        tags=["UEBA"])

# Intelligence & Analytics
app.include_router(ai_router,          tags=["AI"])
app.include_router(audit_router,       tags=["Audit"])
app.include_router(compliance_router,  tags=["Compliance"])
app.include_router(export_router,      tags=["Export"])
app.include_router(ioc_router,         tags=["IOC"])
app.include_router(suppression_router, tags=["Suppression"])
app.include_router(webhook_router,     tags=["Webhook"])

# New v3 features
app.include_router(ml_router,          tags=["ML"])
app.include_router(forecast_router,    tags=["Forecast"])
app.include_router(playbooks_router,   tags=["Playbooks"])
app.include_router(network_router,     tags=["Network"])
app.include_router(mitre_router,       tags=["MITRE"])
app.include_router(pivot_router,       tags=["Pivot"])


# ── Background alert pipeline control ──
# Auto-runs on server boot AND on every /dashboard refresh so alerts stream in
# one-by-one via WebSocket. Set AUTO_PIPELINE=0 to disable auto-boot.
_pipeline_proc: "subprocess.Popen | None" = None


def pipeline_is_running() -> bool:
    return _pipeline_proc is not None and _pipeline_proc.poll() is None


def stop_pipeline() -> None:
    global _pipeline_proc
    if pipeline_is_running():
        _pipeline_proc.terminate()
        try:
            _pipeline_proc.wait(timeout=5)
        except Exception:
            _pipeline_proc.kill()
    _pipeline_proc = None


def launch_pipeline() -> bool:
    """Spawn run.py as a background subprocess. No-op if already running."""
    global _pipeline_proc
    if pipeline_is_running():
        return False
    project_root = Path(__file__).resolve().parent.parent
    run_script = project_root / "run.py"
    if not run_script.exists():
        return False
    log_path = project_root / "pipeline.log"
    try:
        log_f = open(log_path, "ab", buffering=0)
        _pipeline_proc = subprocess.Popen(
            [sys.executable, str(run_script)],
            cwd=str(project_root),
            stdout=log_f,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        print(f"[pipeline] launched (pid={_pipeline_proc.pid}) — logs: {log_path}")
        return True
    except Exception as e:
        print(f"[pipeline] failed to launch: {e}")
        return False


@app.on_event("startup")
def _on_startup():
    if os.getenv("AUTO_PIPELINE", "1") != "0":
        launch_pipeline()


@app.on_event("shutdown")
def _on_shutdown():
    stop_pipeline()
