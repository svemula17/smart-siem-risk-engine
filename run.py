from app.database import SessionLocal
from app.evaluation.confusion_matrix import calculate_evaluation_summary
from app.evaluation.evaluator import evaluate_alert
from app.ingestion.loader import load_all_raw_alerts
from app.ingestion.validator import validate_raw_alert
from app.main import init_db
from app.normalization.mapper import normalize_alert
from app.reporting.report_generator import (
    generate_evaluation_summary_report,
    generate_incident_report,
)
from app.response.responder import respond_to_alert
from app.scoring.score_helpers import get_risk_band
from app.scoring.scorer import score_alert
from app.services.alert_service import (
    save_normalized_alert,
    save_raw_alert,
    save_scored_alert,
)
from app.services.evaluation_service import save_evaluation_result
import requests

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    init_db()
    db = SessionLocal()

    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)
    evaluation_results = []

    print(f"\nLoaded {len(alerts)} raw alerts\n")

    try:
        for alert in alerts:
            is_valid = validate_raw_alert(alert)
            normalized = normalize_alert(alert)
            scored = score_alert(normalized)
            scored = respond_to_alert(normalized, scored, db=db)
            evaluation = evaluate_alert(normalized, scored)

            save_raw_alert(db, alert)
            save_normalized_alert(db, normalized)
            save_scored_alert(db, scored)
            save_evaluation_result(db, evaluation)

            evaluation_results.append(evaluation)

            incident_report_path = generate_incident_report(
                raw_alert=alert,
                normalized_alert=normalized,
                scored_alert=scored,
                evaluation=evaluation,
            )

            risk_band = get_risk_band(scored.risk_score)

            from app.services.geoip_service import geoip_engine
            location = geoip_engine.get_location(normalized.source_ip) if normalized.source_ip else None
            lat, lon, country, city = None, None, None, None
            if location:
                lat, lon, country, city = location.get('lat'), location.get('lon'), location.get('country'), location.get('city')

            # Broadcast to real-time dashboard
            try:
                alert_html = f"""
                <tr class="alert-row highlight-new">
                    <td class="mono id-cell" title="New Alert">*Live*</td>
                    <td class="mono id-cell" title="{alert.id}">{alert.id}</td>
                    <td class="mono score-renderer" data-score="{scored.risk_score}">{scored.risk_score}/100</td>
                    <td>
                        <span class="badge badge-action badge-{scored.recommended_action.split('_')[0]}">
                            {scored.recommended_action.replace('_', ' ')}
                        </span>
                    </td>
                    <td style="color: var(--text-secondary); font-size: 0.8125rem;">
                        {scored.action_taken.replace('_', ' ').title()}
                    </td>
                </tr>
                """
                payload = {
                    "alert_html": alert_html,
                    "risk_score": scored.risk_score,
                    "recommended_action": scored.recommended_action,
                    "action_taken": scored.action_taken,
                    "mitre_ids": normalized.mitre_ids,
                    "lat": lat,
                    "lon": lon,
                    "country": country,
                    "city": city
                }
                requests.post("http://127.0.0.1:8000/api/internal/broadcast", json=payload, timeout=1)
            except requests.exceptions.RequestException:
                pass # Dashboard might not be running, ignore

            # ----------------------------------------------------
            # Dispatch Webhook Notifications (Feature 5)
            # ----------------------------------------------------
            try:
                from app.response.notifications import notifier
                alert_dict = {
                    "alert_id": alert.id,
                    "risk_score": scored.risk_score,
                    "recommended_action": scored.recommended_action,
                    "action_taken": scored.action_taken,
                    "processed_at": scored.processed_at,
                    "score_reasons": scored.score_reasons
                }
                notifier.send_discord_alert(alert_dict, alert.message)
            except Exception as e:
                print(f"Notification error: {e}")

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

    finally:
        db.close()


if __name__ == "__main__":
    main()