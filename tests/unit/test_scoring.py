from app.constants import HIGH_RISK_MAX, LOW_RISK_MAX, MEDIUM_RISK_MAX
from app.normalization.mapper import normalize_alert
from app.scoring.score_helpers import cap_score, get_recommended_action, get_risk_band
from app.scoring.scorer import score_alert


def test_cap_score():
    assert cap_score(150) == 100
    assert cap_score(42) == 42


def test_risk_bands_cover_full_range():
    assert get_risk_band(0) == "LOW"
    assert get_risk_band(LOW_RISK_MAX + 1) == "MEDIUM"
    assert get_risk_band(MEDIUM_RISK_MAX + 1) == "HIGH"
    assert get_risk_band(HIGH_RISK_MAX + 1) == "CRITICAL"
    assert get_risk_band(100) == "CRITICAL"


def test_action_escalates_with_band():
    actions = {get_recommended_action(s) for s in (0, LOW_RISK_MAX + 1, MEDIUM_RISK_MAX + 1, 100)}
    assert len(actions) == 4  # each band maps to a distinct action


def test_score_alert_bounds_and_reasons(raw_alerts):
    for raw in raw_alerts:
        scored = score_alert(normalize_alert(raw))
        assert 0 <= scored.risk_score <= 100
        assert scored.alert_id == raw.id
        assert isinstance(scored.score_reasons, list)
        assert scored.recommended_action == get_recommended_action(scored.risk_score)


def test_malicious_scores_above_benign_on_average(raw_alerts):
    benign, malicious = [], []
    for raw in raw_alerts:
        scored = score_alert(normalize_alert(raw))
        (malicious if raw.ground_truth_label == "MALICIOUS" else benign).append(scored.risk_score)
    assert sum(malicious) / len(malicious) > sum(benign) / len(benign)
