"""
AI / Claude Routes — Incident summarization, attack explanations, false-positive feedback.
"""
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import (
    FalsePositiveDB, NormalizedAlertDB, ScoredAlertDB,
)
from app.services.claude_ai_service import (
    explain_attack_type, generate_incident_summary, investigator_chat,
)
from app.services.audit_logger import log_action

router = APIRouter()


class SummarizeRequest(BaseModel):
    attack_type: str
    risk_score: int
    source_ip: str = ""
    affected_count: int = 1
    mitre_ids: list[str] = []


class FalsePositiveRequest(BaseModel):
    raw_alert_id: str
    analyst: str = "admin"
    reason: str = ""


@router.post("/api/ai/summarize")
def summarize_incident(req: SummarizeRequest):
    """Generate an AI-powered incident summary."""
    result = generate_incident_summary(
        attack_type=req.attack_type,
        risk_score=req.risk_score,
        source_ip=req.source_ip,
        affected_count=req.affected_count,
        mitre_ids=req.mitre_ids,
    )
    return result


class ChatRequest(BaseModel):
    question: str


@router.post("/api/ai/chat")
def ai_chat(req: ChatRequest):
    """AI investigator: answers questions grounded in current SIEM data."""
    from collections import Counter
    db = SessionLocal()
    try:
        scored = db.query(ScoredAlertDB).order_by(desc(ScoredAlertDB.id)).limit(500).all()
        norms = db.query(NormalizedAlertDB).order_by(desc(NormalizedAlertDB.id)).limit(500).all()
        from app.models.db_models import IncidentDB as _Inc
        incidents = db.query(_Inc).order_by(desc(_Inc.created_at)).limit(20).all()

        attack_counts = Counter(n.attack_type or "Unknown" for n in norms)
        ip_counts = Counter(n.source_ip for n in norms if n.source_ip)
        high_risk = sum(1 for s in scored if s.risk_score >= 70)

        context = {
            "totals": {
                "alerts": len(scored),
                "incidents": len(incidents),
                "high_risk": high_risk,
                "hours": 24,
            },
            "top_attacks": [
                {"attack_type": k, "count": v}
                for k, v in attack_counts.most_common(8)
            ],
            "top_ips": [
                {"ip": k, "count": v} for k, v in ip_counts.most_common(8)
            ],
            "recent_incidents": [
                {"id": i.id, "title": i.title, "severity": i.severity,
                 "status": i.status, "created_at": i.created_at}
                for i in incidents
            ],
        }
        return investigator_chat(req.question, context)
    finally:
        db.close()


@router.get("/api/ai/explain/{attack_type}")
def explain_attack(attack_type: str):
    """Return a plain-English explanation of an attack type."""
    explanation = explain_attack_type(attack_type)
    return {"attack_type": attack_type, "explanation": explanation}


@router.post("/api/ai/false-positive")
def mark_false_positive(req: FalsePositiveRequest):
    """Analyst marks an alert as a false positive for ML retraining."""
    db = SessionLocal()
    try:
        # Look up the alert
        scored = db.query(ScoredAlertDB).filter(
            ScoredAlertDB.raw_alert_id == req.raw_alert_id
        ).first()
        norm = db.query(NormalizedAlertDB).filter(
            NormalizedAlertDB.raw_alert_id == req.raw_alert_id
        ).first()

        fp = FalsePositiveDB(
            raw_alert_id=req.raw_alert_id,
            analyst=req.analyst,
            reason=req.reason,
            original_risk_score=scored.risk_score if scored else None,
            original_attack_type=norm.attack_type if norm else None,
            marked_at=datetime.utcnow().isoformat(),
        )
        db.add(fp)
        log_action(db, actor=req.analyst, action="mark_false_positive",
                   target=req.raw_alert_id, detail=req.reason)
        db.commit()
        return {"status": "recorded", "alert_id": req.raw_alert_id}
    finally:
        db.close()


@router.get("/api/ai/false-positives")
def get_false_positives(limit: int = 50):
    db = SessionLocal()
    try:
        rows = db.query(FalsePositiveDB).order_by(desc(FalsePositiveDB.id)).limit(limit).all()
        return [
            {
                "id": r.id,
                "raw_alert_id": r.raw_alert_id,
                "analyst": r.analyst,
                "reason": r.reason,
                "original_risk_score": r.original_risk_score,
                "original_attack_type": r.original_attack_type,
                "marked_at": r.marked_at,
            }
            for r in rows
        ]
    finally:
        db.close()


@router.get("/api/ai/fp-stats")
def fp_stats():
    """False positive rate and top FP attack types."""
    from sqlalchemy import func
    db = SessionLocal()
    try:
        total_fp = db.query(func.count(FalsePositiveDB.id)).scalar() or 0
        total_alerts = db.query(func.count(ScoredAlertDB.id)).scalar() or 1
        fp_rate = round(total_fp / total_alerts * 100, 2)

        top_types = (
            db.query(FalsePositiveDB.original_attack_type, func.count(FalsePositiveDB.id).label("cnt"))
            .group_by(FalsePositiveDB.original_attack_type)
            .order_by(func.count(FalsePositiveDB.id).desc())
            .limit(5)
            .all()
        )
        return {
            "total_false_positives": total_fp,
            "fp_rate_pct": fp_rate,
            "top_fp_attack_types": [{"type": r[0], "count": r[1]} for r in top_types],
        }
    finally:
        db.close()
