"""
Audit Logger
Writes immutable audit trail entries to AuditLogDB for every analyst action.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.db_models import AuditLogDB


def log_action(
    db: Session,
    actor: str,
    action: str,
    target: str = None,
    detail: str = None,
    result: str = "success",
) -> AuditLogDB:
    """
    Write one audit log entry.

    Args:
        db:     SQLAlchemy session
        actor:  Who performed the action ("admin", "analyst1", "system")
        action: What was done ("block_ip", "resolve_incident", "create_rule", etc.)
        target: What was acted on (IP address, incident ID, rule name, etc.)
        detail: Optional extra detail (JSON string or free text)
        result: "success" or "failure"
    """
    entry = AuditLogDB(
        actor=actor,
        action=action,
        target=target,
        detail=detail,
        result=result,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(entry)
    db.commit()
    return entry


def get_recent_logs(db: Session, limit: int = 100) -> list:
    """Return the most recent audit log entries."""
    from sqlalchemy import desc
    rows = db.query(AuditLogDB).order_by(desc(AuditLogDB.id)).limit(limit).all()
    return [
        {
            "id": r.id,
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "detail": r.detail,
            "result": r.result,
            "created_at": r.created_at,
        }
        for r in rows
    ]


def get_actor_summary(db: Session) -> list:
    """Return action counts grouped by actor."""
    from sqlalchemy import func
    rows = (
        db.query(AuditLogDB.actor, func.count(AuditLogDB.id).label("count"))
        .group_by(AuditLogDB.actor)
        .order_by(func.count(AuditLogDB.id).desc())
        .all()
    )
    return [{"actor": r[0], "count": r[1]} for r in rows]
