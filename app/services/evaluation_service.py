from sqlalchemy.orm import Session

from app.models.db_models import EvaluationResultDB
from app.models.evaluation_result import EvaluationResult


def save_evaluation_result(db: Session, evaluation_result: EvaluationResult) -> None:
    db_record = EvaluationResultDB(
        raw_alert_id=evaluation_result.alert_id,
        ground_truth_label=evaluation_result.ground_truth_label,
        predicted_band=evaluation_result.predicted_risk_band,
        expected_band=evaluation_result.expected_risk_band,
        is_correct_band=evaluation_result.is_correct_band,
        predicted_action=evaluation_result.predicted_action,
        expected_action=evaluation_result.expected_action,
        is_correct_action=evaluation_result.is_correct_action,
    )
    db.add(db_record)
    db.commit()
