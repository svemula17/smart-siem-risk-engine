from app.evaluation.metrics import GROUND_TRUTH_TO_ACTION, GROUND_TRUTH_TO_RISK_BAND
from app.models.evaluation_result import EvaluationResult
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.scoring.score_helpers import get_risk_band


def evaluate_alert(normalized_alert: NormalizedAlert, scored_alert: ScoredAlert) -> EvaluationResult:
    ground_truth = normalized_alert.ground_truth_label.upper()

    predicted_risk_band = get_risk_band(scored_alert.risk_score)
    predicted_action = scored_alert.recommended_action

    expected_risk_band = GROUND_TRUTH_TO_RISK_BAND.get(ground_truth, "UNKNOWN")
    expected_action = GROUND_TRUTH_TO_ACTION.get(ground_truth, "unknown")

    is_correct_band = predicted_risk_band == expected_risk_band
    is_correct_action = predicted_action == expected_action

    return EvaluationResult(
        alert_id=normalized_alert.alert_id,
        ground_truth_label=ground_truth,
        predicted_risk_band=predicted_risk_band,
        predicted_action=predicted_action,
        expected_risk_band=expected_risk_band,
        expected_action=expected_action,
        is_correct_band=is_correct_band,
        is_correct_action=is_correct_action,
    )