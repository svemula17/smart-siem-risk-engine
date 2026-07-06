"""Map parsed syslog/CEF messages onto the internal RawAlert model so they
flow through the standard pipeline (normalize → score → respond → ...)."""
import re
import uuid
from datetime import datetime

from app.ingestion.syslog.cef import CEFEvent, is_cef, parse_cef
from app.ingestion.syslog.parser import SyslogMessage, parse_syslog
from app.models.raw_alert import EntityIds, Metadata, RawAlert, SuricataLog, ThreatData

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# syslog severity (0 worst..7) -> our raw_severity (0 benign..3 critical)
_SYSLOG_SEVERITY_MAP = {0: 3, 1: 3, 2: 3, 3: 2, 4: 2, 5: 1, 6: 0, 7: 0}


def _cef_severity(severity: int) -> int:
    """CEF 0-10 -> raw_severity 0-3."""
    if severity >= 9:
        return 3
    if severity >= 7:
        return 2
    if severity >= 4:
        return 1
    return 0


def _extract_ips(text: str) -> list[str]:
    return _IP_RE.findall(text or "")


def map_syslog_to_raw_alert(line: str, peer_host: str = "") -> RawAlert:
    """Convert one syslog line (optionally CEF) into a RawAlert."""
    parsed: SyslogMessage = parse_syslog(line)
    now = datetime.utcnow().isoformat()

    # Detect CEF on the original line — the 3164 parser may consume "CEF:" as the app tag
    cef: CEFEvent | None = parse_cef(line) if is_cef(line) else None

    if cef:
        message = f"{cef.vendor} {cef.product}: {cef.name}"
        raw_severity = _cef_severity(cef.severity)
        src_ip = cef.extensions.get("src") or cef.extensions.get("sourceAddress")
        dst_ip = cef.extensions.get("dst") or cef.extensions.get("destinationAddress")
        user = cef.extensions.get("suser") or cef.extensions.get("sourceUserName")
        ips = [ip for ip in (src_ip, dst_ip) if ip]
        signature_id = cef.signature_id
        signature = cef.name
    else:
        message = parsed.message
        raw_severity = _SYSLOG_SEVERITY_MAP.get(parsed.severity, 1)
        ips = _extract_ips(parsed.message)
        src_ip = ips[0] if ips else None
        user = None
        match = re.search(r"for (?:invalid user )?(\w+) from", parsed.message)
        if match:
            user = match.group(1)
        signature_id = f"{parsed.app}.{parsed.severity}"
        signature = parsed.message[:120]

    entity_ids = EntityIds(
        ip=[src_ip] if src_ip else [],
        ips=ips,
        user=[user] if user else [],
        host=[parsed.host] if parsed.host not in ("", "unknown") else ([peer_host] if peer_host else []),
    )

    metadata = Metadata(
        mitre_info=[],
        suricata_logs=[SuricataLog(
            category="syslog",
            severity=raw_severity,
            signature=signature or message[:120],
            signature_id=signature_id,
            mitre_ids=[],
        )],
        threat=ThreatData(indicator=[]),
    )

    return RawAlert(
        id=str(uuid.uuid4()),
        group="SYSLOG",
        type="cef_event" if cef else "syslog_event",
        message=message,
        source=f"syslog:{parsed.host if parsed.host != 'unknown' else peer_host or 'unknown'}",
        status="new",
        start_time=parsed.timestamp or now,
        end_time=parsed.timestamp or now,
        raw_severity=raw_severity,
        ground_truth_label="UNLABELED",
        entity_ids=entity_ids,
        metadata=metadata,
    )
