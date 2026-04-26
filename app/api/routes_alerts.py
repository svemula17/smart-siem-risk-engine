from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import BlockedIPDB, NormalizedAlertDB, RawAlertDB, ScoredAlertDB
from app.services.audit_logger import log_action
from app.services.incident_service import create_incident

router = APIRouter()


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block from analyst"
    raw_alert_id: str = ""


@router.post("/api/v1/alerts/block-ip")
def block_ip(req: BlockIPRequest):
    """Quick-action: add an IP to the blocklist."""
    db = SessionLocal()
    try:
        existing = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == req.ip).first()
        if existing:
            return {"status": "already_blocked", "ip": req.ip}
        entry = BlockedIPDB(
            ip_address=req.ip,
            raw_alert_id=req.raw_alert_id or "manual",
            reason=req.reason,
            is_simulated=True,
        )
        db.add(entry)
        log_action(db, actor="admin", action="block_ip", target=req.ip, detail=req.reason)
        db.commit()
        return {"status": "blocked", "ip": req.ip}
    finally:
        db.close()


class CreateIncidentRequest(BaseModel):
    raw_alert_id: str
    title: str = ""
    severity: str = "High"


@router.post("/api/v1/alerts/create-incident")
def create_incident_from_alert(req: CreateIncidentRequest):
    """Quick-action: spin up an incident from an alert."""
    db = SessionLocal()
    try:
        norm = db.query(NormalizedAlertDB).filter(
            NormalizedAlertDB.raw_alert_id == req.raw_alert_id
        ).first()
        scored = db.query(ScoredAlertDB).filter(
            ScoredAlertDB.raw_alert_id == req.raw_alert_id
        ).first()
        if not norm:
            raise HTTPException(status_code=404, detail="Alert not found")
        title = req.title or f"{norm.attack_type or 'Threat'} from {norm.source_ip or 'unknown'}"
        desc_text = (
            f"Manually escalated from alert {req.raw_alert_id}. "
            f"Attack: {norm.attack_type}, Risk: {scored.risk_score if scored else 'n/a'}, "
            f"Source: {norm.source_ip or '—'}, Signature: {norm.signature or '—'}"
        )
        inc = create_incident(db, title, desc_text, req.severity, [req.raw_alert_id])
        log_action(db, actor="admin", action="create_incident",
                   target=inc.id, detail=f"from alert {req.raw_alert_id}")
        return {"status": "created", "incident_id": inc.id}
    finally:
        db.close()


@router.get("/raw-alerts")
def get_raw_alerts() -> list[dict]:
    db = SessionLocal()
    try:
        alerts = db.query(RawAlertDB).order_by(RawAlertDB.created_at).all()
        return [
            {
                "id": alert.id,
                "source": alert.source,
                "group": alert.group_name,
                "type": alert.type,
                "message": alert.message,
                "ground_truth_label": alert.ground_truth_label,
                "created_at": alert.created_at,
            }
            for alert in alerts
        ]
    finally:
        db.close()


@router.get("/scored-alerts")
def get_scored_alerts() -> list[dict]:
    db = SessionLocal()
    try:
        rows = (
            db.query(ScoredAlertDB, NormalizedAlertDB)
            .outerjoin(NormalizedAlertDB, ScoredAlertDB.raw_alert_id == NormalizedAlertDB.raw_alert_id)
            .order_by(desc(ScoredAlertDB.id))
            .limit(500)
            .all()
        )
        return [
            {
                "id": scored.id,
                "raw_alert_id": scored.raw_alert_id,
                "risk_score": scored.risk_score,
                "recommended_action": scored.recommended_action,
                "action_taken": scored.action_taken,
                "processed_at": scored.processed_at,
                "attack_type": norm.attack_type if norm else "Unknown Threat",
                "source_ip": norm.source_ip if norm else None,
            }
            for scored, norm in rows
        ]
    finally:
        db.close()


@router.get("/blocked-ips")
def get_blocked_ips() -> list[dict]:
    db = SessionLocal()
    try:
        blocked = db.query(BlockedIPDB).order_by(desc(BlockedIPDB.id)).all()
        return [
            {
                "id": entry.id,
                "ip_address": entry.ip_address,
                "raw_alert_id": entry.raw_alert_id,
                "reason": entry.reason,
                "is_simulated": entry.is_simulated,
            }
            for entry in blocked
        ]
    finally:
        db.close()
