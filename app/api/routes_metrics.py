from fastapi import APIRouter
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import EvaluationResultDB

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