from app.models.raw_alert import RawAlert
from app.models.normalized_alert import NormalizedAlert
from app.normalization.extractors import (
    extract_attack_type,
    extract_category,
    extract_host,
    extract_mitre_ids,
    extract_signature,
    extract_signature_id,
    extract_source_ip,
    extract_threat_indicator_type,
)


def normalize_alert(raw_alert: RawAlert) -> NormalizedAlert:

    source_ip = extract_source_ip(raw_alert)
    host = extract_host(raw_alert)

    category = extract_category(raw_alert)
    signature = extract_signature(raw_alert)
    signature_id = extract_signature_id(raw_alert)
    mitre_ids = extract_mitre_ids(raw_alert)
    threat_indicator_type = extract_threat_indicator_type(raw_alert)
    attack_type = extract_attack_type(raw_alert)

    normalized = NormalizedAlert(
        alert_id=raw_alert.id,
        source=raw_alert.source,
        group=raw_alert.group,
        event_type="network_signature_alert",
        title=raw_alert.message,
        source_ip=source_ip,
        target_ip=None,
        username=None,
        host=host,
        start_time=raw_alert.start_time,
        end_time=raw_alert.end_time,
        raw_severity=raw_alert.raw_severity,
        category=category,
        signature=signature,
        signature_id=signature_id,
        mitre_ids=mitre_ids,
        threat_indicator_type=threat_indicator_type,
        attack_type=attack_type,
        ground_truth_label=raw_alert.ground_truth_label,
    )

    return normalized