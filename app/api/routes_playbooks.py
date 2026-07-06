"""
Playbook Routes — List playbooks, execution log, toggle active.
"""
import json
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import PlaybookDB, PlaybookExecutionDB
from app.services.audit_logger import log_action

router = APIRouter()


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    trigger_condition_json: str = "{}"
    actions_json: str = "[]"


@router.get("/api/v1/playbooks/")
def list_playbooks():
    db = SessionLocal()
    try:
        pbs = db.query(PlaybookDB).order_by(desc(PlaybookDB.id)).all()
        result = []
        for p in pbs:
            try:
                cond = json.loads(p.trigger_condition_json)
                trigger_summary = ", ".join(f"{k}={v}" for k, v in cond.items()) if cond else "Always"
            except Exception:
                trigger_summary = p.trigger_condition_json[:40]

            try:
                acts = json.loads(p.actions_json)
                action_summary = ", ".join(a.get("type", "?") for a in acts) if acts else "—"
            except Exception:
                action_summary = "—"

            result.append({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "trigger_summary": trigger_summary,
                "action_summary": action_summary,
                "is_active": p.is_active,
                "trigger_condition_json": p.trigger_condition_json,
                "actions_json": p.actions_json,
            })
        return result
    finally:
        db.close()


@router.post("/api/v1/playbooks/")
def create_playbook(pb: PlaybookCreate):
    db = SessionLocal()
    try:
        new_pb = PlaybookDB(
            name=pb.name,
            description=pb.description,
            trigger_condition_json=pb.trigger_condition_json,
            actions_json=pb.actions_json,
            is_active=True,
        )
        db.add(new_pb)
        log_action(db, actor="admin", action="create_playbook", target=pb.name)
        db.commit()
        return {"status": "created", "id": new_pb.id}
    finally:
        db.close()


@router.put("/api/v1/playbooks/{playbook_id}/toggle")
def toggle_playbook(playbook_id: int):
    db = SessionLocal()
    try:
        pb = db.query(PlaybookDB).filter(PlaybookDB.id == playbook_id).first()
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")
        pb.is_active = not pb.is_active
        log_action(db, actor="admin", action="toggle_playbook", target=pb.name,
                   detail=f"is_active={pb.is_active}")
        db.commit()
        return {"status": "toggled", "is_active": pb.is_active}
    finally:
        db.close()


@router.get("/api/v1/playbooks/executions")
def get_executions(limit: int = 100):
    db = SessionLocal()
    try:
        rows = db.query(PlaybookExecutionDB).order_by(
            desc(PlaybookExecutionDB.id)
        ).limit(limit).all()
        return {
            "executions": [
                {
                    "id": r.id,
                    "playbook_id": r.playbook_id,
                    "playbook_name": r.playbook_name,
                    "raw_alert_id": r.raw_alert_id,
                    "action_type": r.action_type,
                    "target": r.target,
                    "success": r.success,
                    "error_detail": r.error_detail,
                    "executed_at": r.executed_at,
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@router.post("/api/v1/playbooks/executions")
def log_execution(
    playbook_id: int,
    playbook_name: str,
    action_type: str,
    target: str = "",
    raw_alert_id: str = "",
    success: bool = True,
    error_detail: str = "",
):
    """Internal: record a playbook execution event."""
    db = SessionLocal()
    try:
        rec = PlaybookExecutionDB(
            playbook_id=playbook_id,
            playbook_name=playbook_name,
            raw_alert_id=raw_alert_id or None,
            action_type=action_type,
            target=target or None,
            success=success,
            error_detail=error_detail or None,
            executed_at=datetime.utcnow().isoformat(),
        )
        db.add(rec)
        db.commit()
        return {"status": "recorded", "id": rec.id}
    finally:
        db.close()
