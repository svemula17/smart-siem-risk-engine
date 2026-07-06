"""Sigma detection rule management."""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.sigma.engine import sigma_engine
from app.detection.sigma.evaluator import evaluate
from app.detection.sigma.parser import SigmaParseError, parse_rule
from app.models.db_models import NormalizedAlertDB, SigmaMatchDB, SigmaRuleDB

router = APIRouter(prefix="/api/v1/sigma")


class SigmaUpload(BaseModel):
    yaml_text: str


class SigmaTest(BaseModel):
    yaml_text: str
    sample_size: int = 100


def _serialize(row: SigmaRuleDB) -> dict:
    return {
        "id": row.id,
        "rule_uid": row.rule_uid,
        "title": row.title,
        "level": row.level,
        "tags": json.loads(row.tags_json or "[]"),
        "source": row.source,
        "is_active": row.is_active,
        "created_at": row.created_at,
    }


@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    sigma_engine.sync_bundled_rules(db)
    rows = db.query(SigmaRuleDB).order_by(SigmaRuleDB.level.desc(), SigmaRuleDB.title).all()
    match_counts = dict(
        db.query(SigmaMatchDB.rule_uid, func.count(SigmaMatchDB.id))
        .group_by(SigmaMatchDB.rule_uid)
        .all()
    )
    out = []
    for row in rows:
        d = _serialize(row)
        d["match_count"] = match_counts.get(row.rule_uid, 0)
        out.append(d)
    return {"rules": out}


@router.get("/rules/{rule_id}/yaml")
def get_rule_yaml(rule_id: int, db: Session = Depends(get_db)):
    row = db.query(SigmaRuleDB).filter_by(id=rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"rule_uid": row.rule_uid, "yaml_text": row.yaml_text}


@router.post("/rules")
def upload_rule(req: SigmaUpload, db: Session = Depends(get_db)):
    try:
        rule = parse_rule(req.yaml_text)
    except SigmaParseError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None

    existing = db.query(SigmaRuleDB).filter_by(rule_uid=rule.rule_uid).first()
    if existing:
        existing.title = rule.title
        existing.level = rule.level
        existing.tags_json = json.dumps(rule.tags)
        existing.yaml_text = req.yaml_text
        db.commit()
        sigma_engine.invalidate_cache()
        return {"status": "updated", "rule": _serialize(existing)}

    row = SigmaRuleDB(
        rule_uid=rule.rule_uid, title=rule.title, level=rule.level,
        tags_json=json.dumps(rule.tags), yaml_text=req.yaml_text,
        source="upload", is_active=True,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(row)
    db.commit()
    sigma_engine.invalidate_cache()
    return {"status": "created", "rule": _serialize(row)}


@router.patch("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int, db: Session = Depends(get_db)):
    row = db.query(SigmaRuleDB).filter_by(id=rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    row.is_active = not row.is_active
    db.commit()
    sigma_engine.invalidate_cache()
    return {"status": "ok", "rule_uid": row.rule_uid, "is_active": row.is_active}


@router.post("/test")
def test_rule(req: SigmaTest, db: Session = Depends(get_db)):
    """Dry-run a rule against the most recent normalized alerts."""
    try:
        rule = parse_rule(req.yaml_text)
    except SigmaParseError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None

    sample = (
        db.query(NormalizedAlertDB)
        .order_by(desc(NormalizedAlertDB.id))
        .limit(min(req.sample_size, 1000))
        .all()
    )
    hits = []
    for norm_row in sample:
        event = {
            "message": norm_row.signature or "",
            "source_ip": norm_row.source_ip,
            "event_type": norm_row.event_type,
            "category": norm_row.category,
            "severity": norm_row.raw_severity,
            "signature": norm_row.signature,
            "attack_type": norm_row.attack_type,
            "mitre_ids": json.loads(norm_row.mitre_ids_json or "[]"),
        }
        try:
            if evaluate(rule, event):
                hits.append({"raw_alert_id": norm_row.raw_alert_id,
                             "attack_type": norm_row.attack_type,
                             "source_ip": norm_row.source_ip})
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"evaluation error: {e}") from None

    return {
        "rule": {"title": rule.title, "level": rule.level},
        "sampled": len(sample),
        "matched": len(hits),
        "hits": hits[:25],
    }


@router.get("/matches")
def recent_matches(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(SigmaMatchDB).order_by(desc(SigmaMatchDB.id)).limit(limit).all()
    return {"matches": [
        {"rule_uid": m.rule_uid, "rule_title": m.rule_title, "level": m.level,
         "raw_alert_id": m.raw_alert_id, "matched_at": m.matched_at}
        for m in rows
    ]}
