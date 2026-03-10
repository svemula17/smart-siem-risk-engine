from app.ingestion.loader import load_all_raw_alerts
from app.ingestion.validator import validate_raw_alert
from app.normalization.mapper import normalize_alert
from app.response.responder import respond_to_alert
from app.scoring.score_helpers import get_risk_band
from app.scoring.scorer import score_alert

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)

    print(f"\nLoaded {len(alerts)} raw alerts\n")

    for alert in alerts:
        is_valid = validate_raw_alert(alert)
        normalized = normalize_alert(alert)
        scored = score_alert(normalized)
        scored = respond_to_alert(normalized, scored)
        risk_band = get_risk_band(scored.risk_score)

        print("RAW ALERT")
        print("ID:", alert.id)
        print("Message:", alert.message)

        print("\nNORMALIZED ALERT")
        print("Source IP:", normalized.source_ip)
        print("Category:", normalized.category)
        print("Signature:", normalized.signature)
        print("MITRE IDs:", normalized.mitre_ids)

        print("\nSCORED ALERT")
        print("Risk Score:", scored.risk_score)
        print("Risk Band:", risk_band)
        print("Recommended Action:", scored.recommended_action)
        print("Action Taken:", scored.action_taken)
        print("Score Reasons:")
        for reason in scored.score_reasons:
            print(f" - {reason}")

        print("\nValid:", is_valid)
        print("-" * 60)


if __name__ == "__main__":
    main()