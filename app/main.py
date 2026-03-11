from fastapi import FastAPI

from app.api.routes_alerts import router as alerts_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_reports import router as reports_router
from app.database import Base, engine

app = FastAPI(title="Smart SIEM Risk Engine API", version="1.0.0")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


init_db()

app.include_router(health_router, tags=["Health"])
app.include_router(alerts_router, tags=["Alerts"])
app.include_router(metrics_router, tags=["Metrics"])
app.include_router(reports_router, tags=["Reports"])
app.include_router(dashboard_router, tags=["Dashboard"])