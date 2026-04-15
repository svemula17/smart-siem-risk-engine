from fastapi import APIRouter
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import BlockedIPDB, NormalizedAlertDB, RawAlertDB, ScoredAlertDB

router = APIRouter()


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
