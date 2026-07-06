import requests

from app.config import settings
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
from app.scoring.scorer import score_alert
from app.services.alert_service import (
    save_normalized_alert,
    save_raw_alert,
    save_scored_alert,
)
from app.services.evaluation_service import save_evaluation_result

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    init_db()
    db = SessionLocal()

    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)
    evaluation_results = []

    print(f"\nStreaming raw alerts from {RAW_ALERTS_DIR}...\n")

    processed_count = 0
    try:
        for alert in alerts:
            processed_count += 1
            validate_raw_alert(alert)
            normalized = normalize_alert(alert)
            scored = score_alert(normalized)

            # --- ML Auto-Triage Hook ---
            from app.services.ml_engine import ml_engine
            if not ml_engine.is_trained:
                ml_engine.train_on_history(db)

            is_anomaly = ml_engine.predict_anomaly(normalized, scored)
            if is_anomaly:
                scored.risk_score = min(100, scored.risk_score + 30)
                # We can append this to reasons directly since it is a Pydantic model
                scored.score_reasons.append("ML Engine Auto-Triage: Isolation Forest Anomaly Detected")
                # Force re-evaluate action based on new boosted score
                if scored.risk_score >= 80:
                    scored.recommended_action = "block_and_report"
                elif scored.risk_score >= 60:
                    scored.recommended_action = "generate_report"
            # ---------------------------

            scored = respond_to_alert(normalized, scored, db=db)
            evaluation = evaluate_alert(normalized, scored)

            save_raw_alert(db, alert)
            save_normalized_alert(db, normalized)
            save_scored_alert(db, scored)
            save_evaluation_result(db, evaluation)

            from app.services.correlation_engine import correlation_engine
            correlation_engine.evaluate_alert(db, scored, normalized)

            from app.services.ueba_engine import ueba_engine
            ueba_engine.update_profile(db, scored, normalized)

            # --- Attack graph: extract entities + edges, run pattern detectors ---
            try:
                from app.graph.extractor import extract_from_alert
                from app.graph.path_detector import detect_patterns
                extract_from_alert(db, normalized, scored)
                focus_keys = []
                if normalized.source_ip:
                    focus_keys.append(f"ip:{normalized.source_ip}")
                if getattr(normalized, "username", None):
                    focus_keys.append(f"user:{normalized.username}")
                if focus_keys:
                    detect_patterns(db, focus_keys)
            except Exception as e:
                print(f"[graph] pipeline hook error: {e}")
            # ---------------------------------------------------------------------

            evaluation_results.append(evaluation)

            generate_incident_report(
                raw_alert=alert,
                normalized_alert=normalized,
                scored_alert=scored,
                evaluation=evaluation,
            )



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
                    "city": city,
                    "is_anomaly": is_anomaly
                }
                requests.post(
                    "http://127.0.0.1:8000/api/internal/broadcast",
                    json=payload,
                    headers={"X-Internal-Token": settings.INTERNAL_API_TOKEN},
                    timeout=1,
                )
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

            if processed_count % 5000 == 0:
                print(f"Processed {processed_count} alerts... (Latest: {alert.id}, Score: {scored.risk_score}, Action: {scored.action_taken})")

        print(f"\nFinished processing {processed_count} alerts.")
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
