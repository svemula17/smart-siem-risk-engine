from app.ingestion.loader import load_all_raw_alerts
from app.ingestion.validator import validate_raw_alert
from app.normalization.mapper import normalize_alert

RAW_ALERTS_DIR = "data/raw_alerts"


def main() -> None:
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)

    print(f"\nLoaded {len(alerts)} raw alerts\n")

    for alert in alerts:

        is_valid = validate_raw_alert(alert)

        normalized = normalize_alert(alert)

        print("RAW ALERT")
        print("ID:", alert.id)
        print("Message:", alert.message)

        print("\nNORMALIZED ALERT")
        print("Source IP:", normalized.source_ip)
        print("Category:", normalized.category)
        print("Signature:", normalized.signature)
        print("MITRE IDs:", normalized.mitre_ids)

        print("\nValid:", is_valid)
        print("-" * 50)


if __name__ == "__main__":
    main()