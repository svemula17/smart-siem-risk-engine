from fastapi import APIRouter
from sqlalchemy import text

from app.database import SessionLocal

router = APIRouter()


@router.get("/health")
@router.get("/api/v1/health")
def health_check() -> dict:
    """Liveness + database connectivity check."""
    db_ok = True
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "up" if db_ok else "down",
        "message": "Smart SIEM API is running",
    }
