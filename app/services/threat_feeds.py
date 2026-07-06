"""Live threat-intel feeds: AbuseIPDB blacklist + AlienVault OTX pulses.

Indicators are written through the existing ioc_manager into the ioc table
(deduped there), tagged with the feed name and a 7-day expiry. Sync state is
tracked per feed in threat_feed_state. Without API keys each feed is a clean
no-op, so the demo works out of the box.
"""
import json
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models.db_models import ThreatFeedStateDB
from app.services.ioc_manager import add_ioc

logger = logging.getLogger(__name__)

FEED_EXPIRY_DAYS = 7

ABUSE_CONFIDENCE_MIN = 75  # AbuseIPDB confidence score threshold


def _severity_from_confidence(confidence: int) -> str:
    if confidence >= 95:
        return "Critical"
    if confidence >= 85:
        return "High"
    return "Medium"


def _expiry() -> str:
    return (datetime.utcnow() + timedelta(days=FEED_EXPIRY_DAYS)).isoformat()


def _record_state(db: Session, feed: str, status: str, items: int) -> None:
    state = db.query(ThreatFeedStateDB).filter_by(feed=feed).first()
    if not state:
        state = ThreatFeedStateDB(feed=feed)
        db.add(state)
    state.last_sync_at = datetime.utcnow().isoformat()
    state.last_status = status
    state.items_synced = items
    db.commit()


def sync_abuseipdb(db: Session) -> int:
    """Pull the AbuseIPDB blacklist (confidence >= 75) into the IOC table."""
    if not settings.ABUSEIPDB_API_KEY:
        _record_state(db, "abuseipdb", "disabled (no API key)", 0)
        return 0
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            params={"confidenceMinimum": ABUSE_CONFIDENCE_MIN, "limit": 500},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        entries = resp.json().get("data", [])
    except Exception as e:
        logger.warning(f"[feeds] AbuseIPDB sync failed: {e}")
        _record_state(db, "abuseipdb", f"error: {e}", 0)
        return 0

    count = 0
    for entry in entries:
        ip = entry.get("ipAddress")
        if not ip:
            continue
        confidence = int(entry.get("abuseConfidenceScore", ABUSE_CONFIDENCE_MIN))
        add_ioc(
            db, "ip", ip,
            severity=_severity_from_confidence(confidence),
            source="AbuseIPDB",
            description=f"Blacklisted with confidence {confidence}",
            tags=["abuseipdb", "blacklist"],
            expires_at=_expiry(),
        )
        count += 1

    _record_state(db, "abuseipdb", "ok", count)
    logger.info(f"[feeds] AbuseIPDB synced {count} indicators")
    return count


_OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


def sync_otx(db: Session) -> int:
    """Pull indicators from subscribed AlienVault OTX pulses into the IOC table."""
    if not settings.OTX_API_KEY:
        _record_state(db, "otx", "disabled (no API key)", 0)
        return 0
    try:
        resp = httpx.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            params={"limit": 20},
            headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            timeout=30,
        )
        resp.raise_for_status()
        pulses = resp.json().get("results", [])
    except Exception as e:
        logger.warning(f"[feeds] OTX sync failed: {e}")
        _record_state(db, "otx", f"error: {e}", 0)
        return 0

    count = 0
    for pulse in pulses:
        pulse_name = pulse.get("name", "OTX pulse")
        for indicator in pulse.get("indicators", []):
            ioc_type = _OTX_TYPE_MAP.get(indicator.get("type"))
            value = indicator.get("indicator")
            if not ioc_type or not value:
                continue
            add_ioc(
                db, ioc_type, value,
                severity="High",
                source="OTX",
                description=pulse_name,
                tags=["otx"] + [str(t) for t in (pulse.get("tags") or [])][:5],
                expires_at=_expiry(),
            )
            count += 1

    _record_state(db, "otx", "ok", count)
    logger.info(f"[feeds] OTX synced {count} indicators")
    return count


def expire_stale_iocs(db: Session) -> int:
    """Deactivate feed-sourced IOCs past their expiry."""
    from app.models.db_models import IOCDB
    now = datetime.utcnow().isoformat()
    stale = (
        db.query(IOCDB)
        .filter(IOCDB.is_active == True)
        .filter(IOCDB.expires_at.isnot(None))
        .filter(IOCDB.expires_at < now)
        .all()
    )
    for ioc in stale:
        ioc.is_active = False
    if stale:
        db.commit()
    return len(stale)


def sync_all(db: Session) -> dict:
    """Run every feed once; returns per-feed counts."""
    result = {
        "abuseipdb": sync_abuseipdb(db),
        "otx": sync_otx(db),
        "expired": expire_stale_iocs(db),
    }
    return result


def get_feed_status(db: Session) -> list[dict]:
    rows = db.query(ThreatFeedStateDB).all()
    known = {r.feed: r for r in rows}
    out = []
    for feed, key in (("abuseipdb", settings.ABUSEIPDB_API_KEY), ("otx", settings.OTX_API_KEY)):
        row = known.get(feed)
        out.append({
            "feed": feed,
            "configured": bool(key),
            "last_sync_at": row.last_sync_at if row else None,
            "last_status": row.last_status if row else "never synced",
            "items_synced": row.items_synced if row else 0,
        })
    return out


async def feed_sync_loop():
    """Background task: periodic sync while the server runs."""
    import asyncio

    from app.database import SessionLocal

    interval = max(settings.THREAT_FEED_SYNC_MINUTES, 5) * 60
    while True:
        try:
            db = SessionLocal()
            try:
                result = sync_all(db)
                logger.info(f"[feeds] periodic sync: {json.dumps(result)}")
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"[feeds] sync loop error: {e}")
        await asyncio.sleep(interval)
