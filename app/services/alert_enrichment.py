"""Async alert enrichment with external data lookups."""
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models.db_models import NormalizedAlertDB, ScoredAlertDB, IOCDB, BlockedIPDB
from app.services.geoip_enrichment import geoip_enrichment

logger = logging.getLogger(__name__)


class AlertEnricher:
    """Enrich alerts with external threat intelligence."""

    def enrich_alert(self, db: Session, alert_id: int) -> Dict[str, Any]:
        """Enrich a scored alert with all available data."""
        norm = db.query(NormalizedAlertDB).filter(NormalizedAlertDB.id == alert_id).first()
        scored = db.query(ScoredAlertDB).filter(ScoredAlertDB.raw_alert_id == norm.raw_alert_id).first()

        enrichment = {
            "geo": None,
            "ioc_match": None,
            "reputation": None,
            "related_alerts": 0,
        }

        if norm.source_ip:
            # GeoIP lookup
            geo_data = geoip_enrichment.get_location(db, norm.source_ip)
            if geo_data:
                enrichment["geo"] = geo_data

            # IOC match lookup
            ioc_match = self._check_ioc(db, norm.source_ip)
            if ioc_match:
                enrichment["ioc_match"] = ioc_match

            # Reputation check
            is_blocked = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == norm.source_ip).first()
            if is_blocked:
                enrichment["reputation"] = "blocked"
            elif ioc_match:
                enrichment["reputation"] = "malicious"

            # Related alerts count
            related_count = db.query(NormalizedAlertDB).filter(
                NormalizedAlertDB.source_ip == norm.source_ip
            ).count()
            enrichment["related_alerts"] = related_count

        return enrichment

    def _check_ioc(self, db: Session, value: str) -> Optional[Dict[str, Any]]:
        """Check if value matches any active IOC."""
        ioc = db.query(IOCDB).filter(
            IOCDB.value == value,
            IOCDB.is_active == True
        ).first()

        if ioc:
            # Check expiry
            if ioc.expires_at:
                try:
                    expires = datetime.fromisoformat(ioc.expires_at)
                    if datetime.utcnow() > expires:
                        return None
                except Exception:
                    pass

            return {
                "ioc_type": ioc.ioc_type,
                "severity": ioc.severity,
                "source": ioc.source,
                "description": ioc.description,
            }
        return None

    def bulk_enrich(self, db: Session, alert_ids: list[int]) -> Dict[int, Dict[str, Any]]:
        """Enrich multiple alerts efficiently."""
        results = {}
        for alert_id in alert_ids:
            try:
                results[alert_id] = self.enrich_alert(db, alert_id)
            except Exception as e:
                logger.error(f"Failed to enrich alert {alert_id}: {e}")
                results[alert_id] = {"error": str(e)}
        return results


alert_enricher = AlertEnricher()
