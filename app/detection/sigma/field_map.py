"""Map Sigma field names onto the flat event dict built from our alerts.

Sigma rules in the wild use many spellings for the same concept; everything
is lower-cased before lookup so `SourceIp`, `src_ip`, and `source.ip` all
resolve to the alert's source_ip.
"""

FIELD_ALIASES = {
    # source / destination addresses
    "src_ip": "source_ip",
    "sourceip": "source_ip",
    "source.ip": "source_ip",
    "source_ip": "source_ip",
    "dst_ip": "target_ip",
    "destinationip": "target_ip",
    "destination.ip": "target_ip",
    "target_ip": "target_ip",
    # identity
    "user": "username",
    "username": "username",
    "targetusername": "username",
    "suser": "username",
    # host
    "host": "host",
    "hostname": "host",
    "computername": "host",
    # event content
    "message": "message",
    "commandline": "message",
    "eventtype": "event_type",
    "event_type": "event_type",
    "category": "category",
    "signature": "signature",
    "signature_id": "signature_id",
    "eventid": "signature_id",
    "attack_type": "attack_type",
    "severity": "severity",
    "source": "source",
    "mitre_ids": "mitre_ids",
}


def build_event(raw_alert, normalized) -> dict:
    """Flatten a (raw, normalized) alert pair into the dict Sigma matches on."""
    return {
        "message": raw_alert.message if raw_alert else normalized.title,
        "source": normalized.source,
        "event_type": normalized.event_type,
        "source_ip": normalized.source_ip,
        "target_ip": normalized.target_ip,
        "username": getattr(normalized, "username", None),
        "host": getattr(normalized, "host", None),
        "category": normalized.category,
        "severity": normalized.raw_severity,
        "signature": normalized.signature,
        "signature_id": normalized.signature_id,
        "attack_type": normalized.attack_type,
        "mitre_ids": normalized.mitre_ids or [],
    }


def resolve_field(event: dict, sigma_field: str):
    key = FIELD_ALIASES.get(sigma_field.lower(), sigma_field.lower())
    return event.get(key)
