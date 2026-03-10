from typing import List, Optional

from app.models.raw_alert import RawAlert


def extract_source_ip(raw_alert: RawAlert) -> Optional[str]:
    if raw_alert.entity_ids.ip:
        return raw_alert.entity_ids.ip[0]
    if raw_alert.entity_ids.ips:
        return raw_alert.entity_ids.ips[0]
    return None


def extract_host(raw_alert: RawAlert) -> Optional[str]:
    if raw_alert.entity_ids.host:
        return raw_alert.entity_ids.host[0]
    return None


def extract_category(raw_alert: RawAlert) -> str:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].category
    return "UNKNOWN"


def extract_signature(raw_alert: RawAlert) -> Optional[str]:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].signature
    return None


def extract_signature_id(raw_alert: RawAlert) -> Optional[str]:
    if raw_alert.metadata.suricata_logs:
        return raw_alert.metadata.suricata_logs[0].signature_id
    return None


def extract_mitre_ids(raw_alert: RawAlert) -> List[str]:
    mitre_ids = []

    if raw_alert.metadata.suricata_logs:
        mitre_ids.extend(raw_alert.metadata.suricata_logs[0].mitre_ids)

    return mitre_ids


def extract_threat_indicator_type(raw_alert: RawAlert) -> Optional[str]:
    indicators = raw_alert.metadata.threat.indicator

    if indicators:
        return indicators[0].type

    return None