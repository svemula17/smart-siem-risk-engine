from app.constants import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_AND_REPORT,
    ACTION_GENERATE_REPORT,
    ACTION_STORE_ONLY,
    HIGH_RISK_MAX,
    LOW_RISK_MAX,
    MEDIUM_RISK_MAX,
)


def cap_score(score: int) -> int:
    return min(score, 100)


def get_risk_band(score: int) -> str:
    if score <= LOW_RISK_MAX:
        return "LOW"
    if score <= MEDIUM_RISK_MAX:
        return "MEDIUM"
    if score <= HIGH_RISK_MAX:
        return "HIGH"
    return "CRITICAL"


def get_recommended_action(score: int) -> str:
    if score <= LOW_RISK_MAX:
        return ACTION_STORE_ONLY
    if score <= MEDIUM_RISK_MAX:
        return ACTION_ALERT_ONLY
    if score <= HIGH_RISK_MAX:
        return ACTION_GENERATE_REPORT
    return ACTION_BLOCK_AND_REPORT
