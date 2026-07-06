"""Demo driver: streams raw alerts from disk through the shared pipeline.

Spawned by the API server in demo mode (or run directly). Broadcasts each
processed alert to the dashboard via the internal HTTP endpoint.
"""
import requests

from app.config import settings
from app.database import SessionLocal
from app.evaluation.confusion_matrix import calculate_evaluation_summary
from app.ingestion.loader import load_all_raw_alerts
from app.main import init_db
from app.reporting.report_generator import generate_evaluation_summary_report
from app.services.pipeline import process_raw_alert

RAW_ALERTS_DIR = "data/raw_alerts"


def broadcast_over_http(payload: dict) -> None:
    try:
        requests.post(
            "http://127.0.0.1:8000/api/internal/broadcast",
            json=payload,
            headers={"X-Internal-Token": settings.INTERNAL_API_TOKEN},
            timeout=1,
        )
    except requests.exceptions.RequestException:
        pass  # Dashboard might not be running, ignore


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
            scored, evaluation = process_raw_alert(
                db, alert, notify=broadcast_over_http, generate_report=True
            )
            evaluation_results.append(evaluation)

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
