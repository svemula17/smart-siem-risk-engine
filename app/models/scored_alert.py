
from pydantic import BaseModel


class ScoredAlert(BaseModel):
    alert_id: str
    risk_score: int
    score_reasons: list[str]
    recommended_action: str
    action_taken: str
    processed_at: str
