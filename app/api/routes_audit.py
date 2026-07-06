"""Audit Log Routes"""
from fastapi import APIRouter

from app.database import SessionLocal
from app.services.audit_logger import get_actor_summary, get_recent_logs

router = APIRouter()

@router.get("/api/v1/audit/")
def get_audit_log(limit: int = 100):
    db = SessionLocal()
    try:
        return {"logs": get_recent_logs(db, limit=limit)}
    finally:
        db.close()

@router.get("/api/v1/audit/actors")
def get_actors():
    db = SessionLocal()
    try:
        return get_actor_summary(db)
    finally:
        db.close()
