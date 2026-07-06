"""Ingestion status endpoints (syslog listener)."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/ingest")


@router.get("/syslog/status")
def syslog_status():
    from app.ingestion.syslog.server import stats
    return stats.snapshot()
