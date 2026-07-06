"""
Suppression Rules Routes — Analyst-defined alert suppression rules.
"""
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import SuppressionRuleDB
from app.services.audit_logger import log_action

router = APIRouter()


class SuppressionRuleCreate(BaseModel):
    name: str
    attack_type: str | None = None
    source_ip: str | None = None
    max_risk_score: int | None = None
    window_minutes: int = 60
    created_by: str = "admin"
    expires_at: str | None = None


@router.get("/api/v1/suppression-rules/")
def list_rules():
    db = SessionLocal()
    try:
        rows = db.query(SuppressionRuleDB).order_by(desc(SuppressionRuleDB.id)).all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "attack_type": r.attack_type,
                "source_ip": r.source_ip,
                "max_risk_score": r.max_risk_score,
                "window_minutes": r.window_minutes,
                "is_active": r.is_active,
                "created_by": r.created_by,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
            }
            for r in rows
        ]
    finally:
        db.close()


@router.post("/api/v1/suppression-rules/")
def create_rule(rule: SuppressionRuleCreate):
    db = SessionLocal()
    try:
        new_rule = SuppressionRuleDB(
            name=rule.name,
            attack_type=rule.attack_type,
            source_ip=rule.source_ip,
            max_risk_score=rule.max_risk_score,
            window_minutes=rule.window_minutes,
            is_active=True,
            created_by=rule.created_by,
            created_at=datetime.utcnow().isoformat(),
            expires_at=rule.expires_at,
        )
        db.add(new_rule)
        log_action(db, actor=rule.created_by, action="create_suppression_rule",
                   target=rule.name, detail=f"attack_type={rule.attack_type}")
        db.commit()
        return {"status": "created", "id": new_rule.id}
    finally:
        db.close()


@router.delete("/api/v1/suppression-rules/{rule_id}")
def delete_rule(rule_id: int):
    db = SessionLocal()
    try:
        rule = db.query(SuppressionRuleDB).filter(SuppressionRuleDB.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        rule.is_active = False
        log_action(db, actor="admin", action="delete_suppression_rule", target=str(rule_id))
        db.commit()
        return {"status": "deactivated"}
    finally:
        db.close()


@router.put("/api/v1/suppression-rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    db = SessionLocal()
    try:
        rule = db.query(SuppressionRuleDB).filter(SuppressionRuleDB.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        rule.is_active = not rule.is_active
        db.commit()
        return {"status": "toggled", "is_active": rule.is_active}
    finally:
        db.close()
