"""
IOC Manager — Indicators of Compromise
CRUD operations for IP, domain, hash, and URL indicators.
Also provides real-time matching against incoming alerts.
"""
import json
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.db_models import IOCDB, NormalizedAlertDB


def add_ioc(
    db: Session,
    ioc_type: str,
    value: str,
    severity: str = "High",
    source: str = "Manual",
    description: str = "",
    tags: list = None,
    expires_at: str = None,
) -> IOCDB:
    """Add or update an IOC entry."""
    existing = db.query(IOCDB).filter(IOCDB.value == value, IOCDB.ioc_type == ioc_type).first()
    if existing:
        existing.severity = severity
        existing.source = source
        existing.description = description or existing.description
        existing.is_active = True
        db.commit()
        return existing

    ioc = IOCDB(
        ioc_type=ioc_type,
        value=value,
        severity=severity,
        source=source,
        description=description,
        tags_json=json.dumps(tags or []),
        is_active=True,
        created_at=datetime.utcnow().isoformat(),
        expires_at=expires_at,
    )
    db.add(ioc)
    db.commit()
    return ioc


def get_all_iocs(db: Session, active_only: bool = True) -> list:
    q = db.query(IOCDB)
    if active_only:
        q = q.filter(IOCDB.is_active == True)
    rows = q.order_by(IOCDB.id.desc()).all()
    return [_serialize(r) for r in rows]


def delete_ioc(db: Session, ioc_id: int) -> bool:
    ioc = db.query(IOCDB).filter(IOCDB.id == ioc_id).first()
    if not ioc:
        return False
    ioc.is_active = False
    db.commit()
    return True


def check_ip_against_ioc(db: Session, ip: str) -> dict | None:
    """Return matching IOC if IP is in the database, else None."""
    if not ip:
        return None
    ioc = db.query(IOCDB).filter(IOCDB.value == ip, IOCDB.ioc_type == "ip", IOCDB.is_active == True).first()
    return _serialize(ioc) if ioc else None


def get_ioc_stats(db: Session) -> dict:
    """Return IOC counts by type and severity."""
    by_type = (
        db.query(IOCDB.ioc_type, func.count(IOCDB.id))
        .filter(IOCDB.is_active == True)
        .group_by(IOCDB.ioc_type)
        .all()
    )
    by_sev = (
        db.query(IOCDB.severity, func.count(IOCDB.id))
        .filter(IOCDB.is_active == True)
        .group_by(IOCDB.severity)
        .all()
    )
    return {
        "total": db.query(func.count(IOCDB.id)).filter(IOCDB.is_active == True).scalar() or 0,
        "by_type": {r[0]: r[1] for r in by_type},
        "by_severity": {r[0]: r[1] for r in by_sev},
    }


def match_alerts_to_ioc(db: Session, limit: int = 50) -> list:
    """Return recent alerts whose source IP matches an active IOC."""
    active_ips = [
        r[0] for r in db.query(IOCDB.value).filter(IOCDB.ioc_type == "ip", IOCDB.is_active == True).all()
    ]
    if not active_ips:
        return []

    from sqlalchemy import desc
    hits = (
        db.query(NormalizedAlertDB)
        .filter(NormalizedAlertDB.source_ip.in_(active_ips))
        .order_by(desc(NormalizedAlertDB.id))
        .limit(limit)
        .all()
    )
    return [
        {
            "source_ip": h.source_ip,
            "attack_type": h.attack_type,
            "category": h.category,
            "raw_alert_id": h.raw_alert_id,
        }
        for h in hits
    ]


def seed_demo_iocs(db: Session) -> int:
    """Seed a handful of demo IOCs for the dashboard."""
    demos = [
        ("ip", "185.220.101.1", "Critical", "TorProject", "Known Tor exit node", ["tor", "anonymizer"]),
        ("ip", "198.51.100.23", "High", "AbuseIPDB", "Reported for SSH brute force", ["brute-force", "ssh"]),
        ("ip", "203.0.113.42", "Critical", "VirusTotal", "Botnet C2 server", ["c2", "botnet"]),
        ("domain", "evil-c2.example.com", "Critical", "Manual", "Known C2 domain", ["c2"]),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e", "High", "Manual", "Malware sample hash", ["malware"]),
        ("url", "http://phish.example.com/login", "High", "Manual", "Phishing page", ["phishing"]),
        ("ip", "192.0.2.100", "Medium", "ThreatFeed", "Suspicious scanner", ["scanner", "recon"]),
    ]
    count = 0
    for ioc_type, value, severity, source, desc, tags in demos:
        existing = db.query(IOCDB).filter(IOCDB.value == value).first()
        if not existing:
            add_ioc(db, ioc_type, value, severity, source, desc, tags)
            count += 1
    return count


def _serialize(ioc: IOCDB) -> dict:
    if not ioc:
        return {}
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "severity": ioc.severity,
        "source": ioc.source,
        "description": ioc.description,
        "tags": json.loads(ioc.tags_json or "[]"),
        "is_active": ioc.is_active,
        "created_at": ioc.created_at,
        "expires_at": ioc.expires_at,
    }
