import logging
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.deps import get_current_user, require_role
from app.api.routes_ai import router as ai_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_api_keys import router as api_keys_router
from app.api.routes_audit import router as audit_router
from app.api.routes_auth import router as auth_router
from app.api.routes_backup import router as backup_router
from app.api.routes_compliance import router as compliance_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_export import router as export_router
from app.api.routes_forecast import router as forecast_router
from app.api.routes_graph import router as graph_router
from app.api.routes_health import router as health_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_ioc import router as ioc_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_mitre import router as mitre_router
from app.api.routes_ml import router as ml_router
from app.api.routes_network import router as network_router
from app.api.routes_pivot import router as pivot_router
from app.api.routes_playbooks import router as playbooks_router
from app.api.routes_reports import router as reports_router
from app.api.routes_reset import router as reset_router
from app.api.routes_rules import router as rules_router
from app.api.routes_sigma import router as sigma_router
from app.api.routes_suppression import router as suppression_router
from app.api.routes_ueba import router as ueba_router
from app.api.routes_webhook import router as webhook_router
from app.config import settings
from app.database import Base, SessionLocal, engine

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))


def init_db() -> None:
    # Create all new tables (idempotent)
    Base.metadata.create_all(bind=engine)

    # Run migrations, then ensure the initial admin user exists
    from app.migrations import Migration
    from app.services.auth_service import auth_service
    db = SessionLocal()
    try:
        migrator = Migration(db)
        migrator.apply_all_pending()
        auth_service.ensure_admin_user(db)
    except Exception as e:
        print(f"[migrations] error: {e}")
    finally:
        db.close()


# ── Background alert pipeline control ──
# The demo pipeline streams sample alerts through the engine so the dashboard
# populates live. Controlled by AUTO_PIPELINE / DEMO_MODE settings.
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
            env={
                **os.environ,
                "PYTHONUNBUFFERED": "1",
                # Share the per-process token so the subprocess can broadcast
                "INTERNAL_API_TOKEN": settings.INTERNAL_API_TOKEN,
            },
        )
        print(f"[pipeline] launched (pid={_pipeline_proc.pid}) — logs: {log_path}")
        return True
    except Exception as e:
        print(f"[pipeline] failed to launch: {e}")
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    # Warm in-memory attack graph + seed graph-aware correlation rules (best-effort)
    try:
        from app.graph.loader import graph_loader
        from app.graph.rules_seed import seed as seed_graph_rules
        seed_graph_rules()
        if graph_loader.available:
            graph_loader.warm()
    except Exception as e:
        print(f"[graph] startup init failed: {e}")

    # Periodic threat-intel feed sync (no-op per feed when keys unset)
    import asyncio

    from app.services.threat_feeds import feed_sync_loop
    feed_task = asyncio.create_task(feed_sync_loop())

    # Syslog listener (RFC 3164/5424 + CEF) when enabled
    syslog_server = None
    if settings.SYSLOG_ENABLED:
        try:
            from app.ingestion.syslog.server import SyslogServer
            syslog_server = SyslogServer()
            await syslog_server.start()
        except Exception as e:
            print(f"[syslog] failed to start: {e}")

    if settings.AUTO_PIPELINE and settings.DEMO_MODE:
        launch_pipeline()

    yield

    feed_task.cancel()
    if syslog_server:
        await syslog_server.stop()
    stop_pipeline()


app = FastAPI(title="Smart SIEM Risk Engine API", version="3.1.0", lifespan=lifespan)

# ── Middleware ──
if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard")


AUTH = [Depends(get_current_user)]
ADMIN = [Depends(require_role("Admin"))]

# Open: health checks, login/logout, signed webhooks.
app.include_router(health_router,      tags=["Health"])
app.include_router(auth_router,        tags=["Authentication"])
app.include_router(webhook_router,     tags=["Webhook"])

# Mixed auth handled inside the router (HTML redirect, WebSocket, internal broadcast).
app.include_router(dashboard_router,   tags=["Dashboard"])

# Admin-only: destructive or key-issuing surfaces.
app.include_router(api_keys_router,    tags=["API Keys"], dependencies=ADMIN)
app.include_router(backup_router,      tags=["Backup"], dependencies=ADMIN)
app.include_router(reset_router,       tags=["Reset"], dependencies=ADMIN)

# Authenticated (session cookie or X-API-Key).
app.include_router(alerts_router,      tags=["Alerts"], dependencies=AUTH)
app.include_router(metrics_router,     tags=["Metrics"], dependencies=AUTH)
app.include_router(reports_router,     tags=["Reports"], dependencies=AUTH)
app.include_router(incidents_router,   tags=["Incidents"], dependencies=AUTH)
app.include_router(rules_router,       tags=["Rules"], dependencies=AUTH)
app.include_router(ueba_router,        tags=["UEBA"], dependencies=AUTH)
app.include_router(ai_router,          tags=["AI"], dependencies=AUTH)
app.include_router(audit_router,       tags=["Audit"], dependencies=AUTH)
app.include_router(compliance_router,  tags=["Compliance"], dependencies=AUTH)
app.include_router(export_router,      tags=["Export"], dependencies=AUTH)
app.include_router(ioc_router,         tags=["IOC"], dependencies=AUTH)
app.include_router(suppression_router, tags=["Suppression"], dependencies=AUTH)
app.include_router(ml_router,          tags=["ML"], dependencies=AUTH)
app.include_router(forecast_router,    tags=["Forecast"], dependencies=AUTH)
app.include_router(playbooks_router,   tags=["Playbooks"], dependencies=AUTH)
app.include_router(network_router,     tags=["Network"], dependencies=AUTH)
app.include_router(mitre_router,       tags=["MITRE"], dependencies=AUTH)
app.include_router(sigma_router,       tags=["Sigma"], dependencies=AUTH)
app.include_router(ingest_router,      tags=["Ingestion"], dependencies=AUTH)
app.include_router(pivot_router,       tags=["Pivot"], dependencies=AUTH)
app.include_router(graph_router,       tags=["Graph"], dependencies=AUTH)
