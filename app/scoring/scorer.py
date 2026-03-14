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

    # ML NLP Model Blended Scoring
    try:
        from app.scoring.ml_model import ml_engine
        
        # We need to ensure text isn't None
        text_to_analyze = alert.title if alert.title else ""
        if text_to_analyze:
            ml_prediction = ml_engine.predict(text_to_analyze)
            
            if ml_prediction != "UNKNOWN":
                reasons.append(f"ML NLP Model predicted '{ml_prediction}' risk band")
                
                # Blend the ML prediction with the heuristic score
                if ml_prediction == "CRITICAL" and total_score < 75:
                    total_score += 15
                    reasons.append("ML Model boosted score due to CRITICAL prediction (+15 points)")
                elif ml_prediction == "LOW" and total_score > 30:
                    total_score -= 15
                    reasons.append("ML Model reduced score due to LOW risk prediction (-15 points)")
    except Exception as e:
        print(f"ML Scoring failed/skipped: {e}")
        pass # Handle case where sklearn isn't installed yet or model fails

    # Threat Intel Integration
    try:
        from app.services.threat_intel import threat_intel
        if alert.source_ip:
            intel = threat_intel.get_intel_for_ip(alert.source_ip)
            if intel and intel["score"] > 60:
                intel_boost = 15
                total_score += intel_boost
                tag_str = ", ".join(intel["tags"]) if intel["tags"] else "Malicious"
                reasons.append(f"Threat Intel [{intel['provider']}]: IP Reputation is Poor ({intel['score']}/100) - Tags: {tag_str} (+{intel_boost} points)")
    except Exception as e:
        print(f"Threat Intel failed: {e}")

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