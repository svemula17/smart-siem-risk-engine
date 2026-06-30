from fastapi import APIRouter, Depends
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_db
from app.models.db_models import (
    EvaluationResultDB, ScoredAlertDB, IncidentDB, BlockedIPDB,
    IPEntityProfileDB, PlaybookExecutionDB, FalsePositiveDB, RawAlertDB
)

router = APIRouter()


@router.get("/evaluation-results")
def get_evaluation_results() -> list[dict]:
    db = SessionLocal()
    try:
        results = db.query(EvaluationResultDB).order_by(desc(EvaluationResultDB.id)).all()
        return [
            {
                "id": result.id,
                "raw_alert_id": result.raw_alert_id,
                "ground_truth_label": result.ground_truth_label,
                "predicted_band": result.predicted_band,
                "expected_band": result.expected_band,
                "is_correct_band": result.is_correct_band,
                "predicted_action": result.predicted_action,
                "expected_action": result.expected_action,
                "is_correct_action": result.is_correct_action,
            }
            for result in results
        ]
    finally:
        db.close()


@router.get("/metrics")
def get_metrics() -> dict:
    db = SessionLocal()
    try:
        results = db.query(EvaluationResultDB).all()
        total = len(results)

        if total == 0:
            return {
                "total_alerts": 0,
                "correct_band_predictions": 0,
                "correct_action_predictions": 0,
                "band_accuracy": 0.0,
                "action_accuracy": 0.0,
            }

        correct_band = sum(1 for result in results if result.is_correct_band)
        correct_action = sum(1 for result in results if result.is_correct_action)

        return {
            "total_alerts": total,
            "correct_band_predictions": correct_band,
            "correct_action_predictions": correct_action,
            "band_accuracy": round((correct_band / total) * 100, 2),
            "action_accuracy": round((correct_action / total) * 100, 2),
        }
    finally:
        db.close()


@router.get("/prometheus")
def prometheus_metrics(db: Session = Depends(get_db)):
    """Return Prometheus-style metrics for monitoring."""
    total_alerts = db.query(func.count(ScoredAlertDB.id)).scalar() or 0
    critical_alerts = db.query(func.count(ScoredAlertDB.id)).filter(ScoredAlertDB.risk_score >= 80).scalar() or 0
    high_alerts = db.query(func.count(ScoredAlertDB.id)).filter((ScoredAlertDB.risk_score >= 60) & (ScoredAlertDB.risk_score < 80)).scalar() or 0
    anomaly_alerts = db.query(func.count(ScoredAlertDB.id)).filter(ScoredAlertDB.is_anomaly == True).scalar() or 0

    open_incidents = db.query(func.count(IncidentDB.id)).filter(IncidentDB.status == "Open").scalar() or 0
    closed_incidents = db.query(func.count(IncidentDB.id)).filter(IncidentDB.status == "Closed").scalar() or 0

    blocked_ips = db.query(func.count(BlockedIPDB.id)).scalar() or 0
    playbook_executions = db.query(func.count(PlaybookExecutionDB.id)).scalar() or 0
    playbook_failures = db.query(func.count(PlaybookExecutionDB.id)).filter(PlaybookExecutionDB.success == False).scalar() or 0

    critical_entities = db.query(func.count(IPEntityProfileDB.id)).filter(IPEntityProfileDB.risk_level == "Critical").scalar() or 0
    high_entities = db.query(func.count(IPEntityProfileDB.id)).filter(IPEntityProfileDB.risk_level == "High").scalar() or 0

    false_positives = db.query(func.count(FalsePositiveDB.id)).scalar() or 0

    metrics = f"""# HELP siem_alerts_total Total number of processed alerts
# TYPE siem_alerts_total counter
siem_alerts_total {total_alerts}

# HELP siem_alerts_critical Critical severity alerts
# TYPE siem_alerts_critical gauge
siem_alerts_critical {critical_alerts}

# HELP siem_alerts_high High severity alerts
# TYPE siem_alerts_high gauge
siem_alerts_high {high_alerts}

# HELP siem_alerts_anomalies Anomalous alerts detected by ML
# TYPE siem_alerts_anomalies gauge
siem_alerts_anomalies {anomaly_alerts}

# HELP siem_incidents_open Open incidents
# TYPE siem_incidents_open gauge
siem_incidents_open {open_incidents}

# HELP siem_incidents_closed Closed incidents
# TYPE siem_incidents_closed counter
siem_incidents_closed {closed_incidents}

# HELP siem_blocked_ips Total IPs blocked
# TYPE siem_blocked_ips counter
siem_blocked_ips {blocked_ips}

# HELP siem_playbook_executions Total playbook executions
# TYPE siem_playbook_executions counter
siem_playbook_executions {playbook_executions}

# HELP siem_playbook_failures Failed playbook executions
# TYPE siem_playbook_failures counter
siem_playbook_failures {playbook_failures}

# HELP siem_entities_critical Critical risk entities
# TYPE siem_entities_critical gauge
siem_entities_critical {critical_entities}

# HELP siem_entities_high High risk entities
# TYPE siem_entities_high gauge
siem_entities_high {high_entities}

# HELP siem_false_positives False positive feedback count
# TYPE siem_false_positives counter
siem_false_positives {false_positives}
"""
    return metrics


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    try:
        db.query(RawAlertDB).limit(1).all()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}