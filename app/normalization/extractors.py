
from app.models.raw_alert import RawAlert
from app.normalization.attack_type_classifier import classify_attack_type


def extract_source_ip(raw_alert: RawAlert) -> str | None:
    if raw_alert.entity_ids.ip:
        return raw_alert.entity_ids.ip[0]
    if raw_alert.entity_ids.ips:
        return raw_alert.entity_ids.ips[0]
    return None


def extract_target_ip(raw_alert: RawAlert) -> str | None:
    """Return second IP in `ips` list (when distinct from source)."""
    ips = raw_alert.entity_ids.ips or []
    src = extract_source_ip(raw_alert)
    for ip in ips:
        if ip and ip != src:
            return ip
    return None


def extract_host(raw_alert: RawAlert) -> str | None:
    if raw_alert.entity_ids.host:
        return raw_alert.entity_ids.host[0]
    return None


def extract_category(raw_alert: RawAlert) -> str:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].category
    return "UNKNOWN"


def extract_signature(raw_alert: RawAlert) -> str | None:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].signature
    return None


def extract_signature_id(raw_alert: RawAlert) -> str | None:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].signature_id
    return None


def extract_mitre_ids(raw_alert: RawAlert) -> list[str]:
    mitre_ids = []

    if raw_alert.metadata.suricata_logs:
        mitre_ids.extend(raw_alert.metadata.suricata_logs[0].mitre_ids)

    return mitre_ids


def extract_threat_indicator_type(raw_alert: RawAlert) -> str | None:
    indicators = raw_alert.metadata.threat.indicator

    if indicators:
        return indicators[0].type

    return None


def extract_attack_type(raw_alert: RawAlert) -> str:
    """Classify the attack type using MITRE IDs, category, and message."""
    mitre_ids = extract_mitre_ids(raw_alert)
    category = extract_category(raw_alert)
    message = raw_alert.message or ""
    return classify_attack_type(mitre_ids, category, message)
