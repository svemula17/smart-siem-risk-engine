from app.ingestion.loader import load_all_raw_alerts
from app.ingestion.validator import validate_raw_alert

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)

    print(f"Loaded {len(alerts)} raw alerts\n")

    for alert in alerts:
        is_valid = validate_raw_alert(alert)
        print(f"Alert ID: {alert.id}")
        print(f"Message: {alert.message}")
        print(f"Ground Truth: {alert.ground_truth_label}")
        print(f"Valid: {is_valid}")
        print("-" * 50)


if __name__ == "__main__":
    main()