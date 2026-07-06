from pydantic import BaseModel


class EvaluationResult(BaseModel):
    alert_id: str
    ground_truth_label: str
    predicted_risk_band: str
    predicted_action: str
    expected_risk_band: str
    expected_action: str
    is_correct_band: bool
    is_correct_action: bool
