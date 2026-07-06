"""
Export Routes — CSV, JSON download endpoints for all major tables.
"""
import csv
import io
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import (
    IOCDB,
    AuditLogDB,
    BlockedIPDB,
    EvaluationResultDB,
    NormalizedAlertDB,
    ScoredAlertDB,
)

router = APIRouter()


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    if not rows:
        rows = [{"message": "no data"}]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/export/scored-alerts")
def export_scored_alerts(fmt: str = "csv"):
    db = SessionLocal()
    try:
        rows_db = (
            db.query(ScoredAlertDB, NormalizedAlertDB)
            .outerjoin(NormalizedAlertDB, ScoredAlertDB.raw_alert_id == NormalizedAlertDB.raw_alert_id)
            .order_by(desc(ScoredAlertDB.id))
            .limit(10000)
            .all()
        )
        rows = [
            {
                "alert_id": s.raw_alert_id,
                "risk_score": s.risk_score,
                "risk_band": (
                    "Critical" if s.risk_score >= 80
                    else "High" if s.risk_score >= 60
                    else "Medium" if s.risk_score >= 30
                    else "Low"
                ),
                "attack_type": n.attack_type if n else "Unknown",
                "source_ip": n.source_ip if n else "",
                "recommended_action": s.recommended_action,
                "action_taken": s.action_taken,
                "processed_at": s.processed_at,
            }
            for s, n in rows_db
        ]
        if fmt == "json":
            return JSONResponse(content=rows)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return _csv_response(rows, f"scored_alerts_{ts}.csv")
    finally:
        db.close()


@router.get("/api/export/blocked-ips")
def export_blocked_ips(fmt: str = "csv"):
    db = SessionLocal()
    try:
        rows = [
            {
                "ip_address": r.ip_address,
                "reason": r.reason,
                "is_simulated": r.is_simulated,
                "raw_alert_id": r.raw_alert_id,
            }
            for r in db.query(BlockedIPDB).all()
        ]
        if fmt == "json":
            return JSONResponse(content=rows)
        return _csv_response(rows, f"blocked_ips_{datetime.utcnow().strftime('%Y%m%d')}.csv")
    finally:
        db.close()


@router.get("/api/export/ioc")
def export_ioc(fmt: str = "csv"):
    db = SessionLocal()
    try:
        rows = [
            {
                "ioc_type": r.ioc_type,
                "value": r.value,
                "severity": r.severity,
                "source": r.source,
                "description": r.description,
                "tags": r.tags_json,
                "is_active": r.is_active,
                "created_at": r.created_at,
            }
            for r in db.query(IOCDB).filter(IOCDB.is_active == True).all()
        ]
        if fmt == "json":
            return JSONResponse(content=rows)
        return _csv_response(rows, f"ioc_export_{datetime.utcnow().strftime('%Y%m%d')}.csv")
    finally:
        db.close()


@router.get("/api/export/audit-log")
def export_audit_log(fmt: str = "csv"):
    db = SessionLocal()
    try:
        rows = [
            {
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "detail": r.detail,
                "result": r.result,
                "created_at": r.created_at,
            }
            for r in db.query(AuditLogDB).order_by(desc(AuditLogDB.id)).limit(5000).all()
        ]
        if fmt == "json":
            return JSONResponse(content=rows)
        return _csv_response(rows, f"audit_log_{datetime.utcnow().strftime('%Y%m%d')}.csv")
    finally:
        db.close()


@router.get("/api/export/evaluation")
def export_evaluation(fmt: str = "csv"):
    db = SessionLocal()
    try:
        rows = [
            {
                "raw_alert_id": r.raw_alert_id,
                "ground_truth": r.ground_truth_label,
                "predicted_band": r.predicted_band,
                "expected_band": r.expected_band,
                "band_correct": r.is_correct_band,
                "predicted_action": r.predicted_action,
                "expected_action": r.expected_action,
                "action_correct": r.is_correct_action,
            }
            for r in db.query(EvaluationResultDB).limit(10000).all()
        ]
        if fmt == "json":
            return JSONResponse(content=rows)
        return _csv_response(rows, f"evaluation_{datetime.utcnow().strftime('%Y%m%d')}.csv")
    finally:
        db.close()
