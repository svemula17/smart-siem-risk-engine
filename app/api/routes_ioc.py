"""
IOC (Indicators of Compromise) Management Routes
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from app.database import SessionLocal
from app.services.ioc_manager import (
    add_ioc, delete_ioc, get_all_iocs, get_ioc_stats,
    match_alerts_to_ioc, seed_demo_iocs,
)
from app.services.audit_logger import log_action

router = APIRouter()


class IOCCreate(BaseModel):
    ioc_type: str          # ip, domain, hash, url
    value: str
    severity: str = "High"
    source: str = "Manual"
    description: str = ""
    tags: List[str] = []
    expires_at: Optional[str] = None


@router.get("/api/v1/ioc/")
def list_iocs(active_only: bool = True):
    db = SessionLocal()
    try:
        return get_all_iocs(db, active_only=active_only)
    finally:
        db.close()


@router.post("/api/v1/ioc/")
def create_ioc(ioc: IOCCreate):
    db = SessionLocal()
    try:
        result = add_ioc(
            db,
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            severity=ioc.severity,
            source=ioc.source,
            description=ioc.description,
            tags=ioc.tags,
            expires_at=ioc.expires_at,
        )
        log_action(db, actor="admin", action="create_ioc", target=ioc.value,
                   detail=f"type={ioc.ioc_type} severity={ioc.severity}")
        return {"status": "created", "id": result.id}
    finally:
        db.close()


@router.delete("/api/v1/ioc/{ioc_id}")
def remove_ioc(ioc_id: int):
    db = SessionLocal()
    try:
        ok = delete_ioc(db, ioc_id)
        if not ok:
            raise HTTPException(status_code=404, detail="IOC not found")
        log_action(db, actor="admin", action="delete_ioc", target=str(ioc_id))
        return {"status": "deactivated"}
    finally:
        db.close()


@router.get("/api/v1/ioc/stats")
def ioc_stats():
    db = SessionLocal()
    try:
        return get_ioc_stats(db)
    finally:
        db.close()


@router.get("/api/v1/ioc/matches")
def ioc_matches():
    """Return recent alerts whose source IP matches an active IOC."""
    db = SessionLocal()
    try:
        return {"matches": match_alerts_to_ioc(db)}
    finally:
        db.close()


@router.post("/api/v1/ioc/seed")
def seed_iocs():
    """Seed demo IOCs for testing."""
    db = SessionLocal()
    try:
        count = seed_demo_iocs(db)
        return {"status": "ok", "seeded": count}
    finally:
        db.close()


@router.get("/api/v1/ioc/check/{ip}")
def check_ip(ip: str):
    """Check if a specific IP is in the IOC database."""
    from app.services.ioc_manager import check_ip_against_ioc
    db = SessionLocal()
    try:
        result = check_ip_against_ioc(db, ip)
        return {"ip": ip, "is_ioc": bool(result), "ioc": result}
    finally:
        db.close()
