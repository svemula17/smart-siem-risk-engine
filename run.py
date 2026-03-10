from app.evaluation.confusion_matrix import calculate_evaluation_summary
from app.evaluation.evaluator import evaluate_alert
from app.ingestion.loader import load_all_raw_alerts
from app.ingestion.validator import validate_raw_alert
from app.normalization.mapper import normalize_alert
from app.reporting.report_generator import (
    generate_evaluation_summary_report,
    generate_incident_report,
)
from app.response.responder import respond_to_alert
from app.scoring.score_helpers import get_risk_band
from app.scoring.scorer import score_alert

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)
    evaluation_results = []

    print(f"\nLoaded {len(alerts)} raw alerts\n")

    for alert in alerts:
        is_valid = validate_raw_alert(alert)
        normalized = normalize_alert(alert)
        scored = score_alert(normalized)
        scored = respond_to_alert(normalized, scored)
        evaluation = evaluate_alert(normalized, scored)

        evaluation_results.append(evaluation)

        incident_report_path = generate_incident_report(
            raw_alert=alert,
            normalized_alert=normalized,
            scored_alert=scored,
            evaluation=evaluation,
        )

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

        print("\nEVALUATION")
        print("Ground Truth:", evaluation.ground_truth_label)
        print("Expected Risk Band:", evaluation.expected_risk_band)
        print("Predicted Risk Band:", evaluation.predicted_risk_band)
        print("Band Correct:", evaluation.is_correct_band)
        print("Expected Action:", evaluation.expected_action)
        print("Predicted Action:", evaluation.predicted_action)
        print("Action Correct:", evaluation.is_correct_action)

        print("\nREPORT")
        print("Incident Report Generated:", incident_report_path)

        print("\nValid:", is_valid)
        print("-" * 60)

    summary = calculate_evaluation_summary(evaluation_results)
    evaluation_report_path = generate_evaluation_summary_report(
        results=evaluation_results,
        summary=summary,
    )

    print("\nFINAL EVALUATION SUMMARY")
    print("Total Alerts:", summary["total_alerts"])
    print("Correct Band Predictions:", summary["correct_band_predictions"])
    print("Correct Action Predictions:", summary["correct_action_predictions"])
    print("Band Accuracy (%):", summary["band_accuracy"])
    print("Action Accuracy (%):", summary["action_accuracy"])
    print("Evaluation Summary Report Generated:", evaluation_report_path)


if __name__ == "__main__":
    main()