"""GeoIP enrichment service for alert and IP data."""
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.db_models import GeoIPCacheDB
from app.utils import is_internal_ip

logger = logging.getLogger(__name__)

class GeoIPEnrichment:
    """Enrich IPs with geolocation data."""

    def __init__(self):
        self.cache_ttl_days = 30

    def get_location(self, db: Session, ip_address: str) -> dict[str, Any] | None:
        """Get cached location for IP, or None if not found."""
        # Don't lookup internal IPs
        if is_internal_ip(ip_address):
            return None

        cached = db.query(GeoIPCacheDB).filter(GeoIPCacheDB.ip_address == ip_address).first()
        if cached:
            # Check if expired
            if cached.expires_at:
                try:
                    expiry = datetime.fromisoformat(cached.expires_at)
                    if datetime.utcnow() < expiry:
                        return {
                            "country": cached.country,
                            "city": cached.city,
                            "latitude": cached.latitude,
                            "longitude": cached.longitude,
                            "isp": cached.isp,
                            "risk_score": cached.risk_score,
                        }
                except Exception:
                    pass

        return None

    def cache_location(
        self,
        db: Session,
        ip_address: str,
        country: str | None = None,
        city: str | None = None,
        latitude: float | None = None,
        longitude: float | None = None,
        isp: str | None = None,
        risk_score: float = 0.0,
    ) -> None:
        """Cache location data for an IP."""
        existing = db.query(GeoIPCacheDB).filter(GeoIPCacheDB.ip_address == ip_address).first()

        now = datetime.utcnow()
        expires_at = now + timedelta(days=self.cache_ttl_days)

        if existing:
            existing.country = country
            existing.city = city
            existing.latitude = latitude
            existing.longitude = longitude
            existing.isp = isp
            existing.risk_score = risk_score
            existing.cached_at = now.isoformat()
            existing.expires_at = expires_at.isoformat()
        else:
            entry = GeoIPCacheDB(
                ip_address=ip_address,
                country=country,
                city=city,
                latitude=latitude,
                longitude=longitude,
                isp=isp,
                risk_score=risk_score,
                cached_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
            )
            db.add(entry)

        db.commit()

    def get_country_risk(self, country: str | None) -> float:
        """Return risk multiplier for a country (0.5 - 2.0)."""
        # Hardcoded risk scores for known high-risk regions
        high_risk_countries = {"KP", "IR", "SY", "CU"}  # OFAC sanctioned
        medium_risk_countries = {"RU", "CN", "KP"}

        if not country:
            return 1.0
        if country in high_risk_countries:
            return 2.0
        if country in medium_risk_countries:
            return 1.5
        return 1.0


geoip_enrichment = GeoIPEnrichment()
