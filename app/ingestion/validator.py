from app.models.raw_alert import RawAlert


def validate_raw_alert(raw_alert: RawAlert) -> bool:
    required_top_fields = [
        raw_alert.id,
        raw_alert.group,
        raw_alert.type,
        raw_alert.message,
        raw_alert.source,
        raw_alert.start_time,
        raw_alert.end_time,
        raw_alert.ground_truth_label,
    ]

    return all(field is not None and field != "" for field in required_top_fields)
