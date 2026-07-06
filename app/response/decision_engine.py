from app.models.scored_alert import ScoredAlert


def decide_action(scored_alert: ScoredAlert) -> str:
    return scored_alert.recommended_action
