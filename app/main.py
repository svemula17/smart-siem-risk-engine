from fastapi import FastAPI

from app.api.routes_alerts import router as alerts_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_reports import router as reports_router
from app.api.routes_reset import router as reset_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_rules import router as rules_router
from app.api.routes_auth import router as auth_router
from app.api.routes_ueba import router as ueba_router

from app.database import Base, engine
from sqlalchemy import text

app = FastAPI(title="Smart SIEM Risk Engine API", version="1.0.0")


def init_db() -> None:
    # Create any new tables (e.g. suppressed_alerts)
    Base.metadata.create_all(bind=engine)

    # Safe column migrations for existing tables
    with engine.connect() as conn:
        # Add attack_type to normalized_alerts if not present
        try:
            conn.execute(text(
                "ALTER TABLE normalized_alerts ADD COLUMN attack_type VARCHAR DEFAULT 'Unknown Threat'"
            ))
            conn.commit()
        except Exception:
            pass  # Column already exists


init_db()

from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard")

app.include_router(health_router, tags=["Health"])
app.include_router(alerts_router, tags=["Alerts"])
app.include_router(metrics_router, tags=["Metrics"])
app.include_router(reports_router, tags=["Reports"])
app.include_router(dashboard_router, tags=["Dashboard"])
app.include_router(reset_router, tags=["Reset"])
app.include_router(incidents_router, tags=["Incidents"])
app.include_router(rules_router, tags=["Rules"])
app.include_router(auth_router, tags=["Authentication"])
app.include_router(ueba_router, tags=["UEBA"])