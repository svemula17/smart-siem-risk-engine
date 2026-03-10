from datetime import datetime

from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.scoring.score_helpers import cap_score, get_recommended_action
from app.scoring.score_rules import (
    score_by_category,
    score_by_group,
    score_by_mitre_ids,
    score_by_raw_severity,
    score_by_threat_indicator,
)


def score_alert(alert: NormalizedAlert) -> ScoredAlert:
    total_score = 0
    reasons = []

    scoring_functions = [
        score_by_category,
        score_by_raw_severity,
        score_by_mitre_ids,
        score_by_threat_indicator,
        score_by_group,
    ]

    for scoring_function in scoring_functions:
        score, score_reasons = scoring_function(alert)
        total_score += score
        reasons.extend(score_reasons)

    total_score = cap_score(total_score)
    recommended_action = get_recommended_action(total_score)

    scored_alert = ScoredAlert(
        alert_id=alert.alert_id,
        risk_score=total_score,
        score_reasons=reasons,
        recommended_action=recommended_action,
        action_taken="none",
        processed_at=datetime.utcnow().isoformat(),
    )

    return scored_alert