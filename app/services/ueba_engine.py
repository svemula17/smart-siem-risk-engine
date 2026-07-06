import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.db_models import IPEntityProfileDB, NormalizedAlertDB, ScoredAlertDB
from app.services.incident_service import create_incident

logger = logging.getLogger(__name__)

class UEBAEngine:
    def __init__(self):
        self.critical_threshold = 200
        self.high_threshold = 100
        self.medium_threshold = 50

    def update_profile(self, db: Session, scored_alert: ScoredAlertDB, normalized_alert: NormalizedAlertDB):
        ip = normalized_alert.source_ip
        if not ip:
            return None

        profile = db.query(IPEntityProfileDB).filter(IPEntityProfileDB.ip_address == ip).first()

        now_str = datetime.utcnow().isoformat()

        if not profile:
            profile = IPEntityProfileDB(
                ip_address=ip,
                total_alerts_seen=1,
                cumulative_risk_score=scored_alert.risk_score,
                risk_level=self._calculate_level(scored_alert.risk_score),
                created_at=now_str,
                updated_at=now_str
            )
            db.add(profile)
        else:
            old_level = profile.risk_level

            profile.total_alerts_seen += 1
            profile.cumulative_risk_score += scored_alert.risk_score
            profile.updated_at = now_str
            profile.risk_level = self._calculate_level(profile.cumulative_risk_score)

            # If Risk Level escalated to High or Critical, generate an anomaly incident
            if profile.risk_level in ["High", "Critical"] and old_level not in ["High", "Critical"]:
                logger.info(f"UEBA Anomaly Detected: Entity {ip} escalated to {profile.risk_level} risk.")

                create_incident(
                    db=db,
                    title=f"UEBA Anomaly: Sustained Suspicious Activity from {ip}",
                    description=f"User Entity Behavior Analytics (UEBA) has flagged IP {ip} for sustained suspicious behavior. They have triggered {profile.total_alerts_seen} alerts with a cumulative risk score of {profile.cumulative_risk_score}.",
                    severity=profile.risk_level,
                    alert_ids=[scored_alert.raw_alert_id] if hasattr(scored_alert, 'raw_alert_id') else []
                )

        try:
            db.commit()
            db.refresh(profile)
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update UEBA profile for {ip}: {e}")

        return profile

    def _calculate_level(self, score: int) -> str:
        if score >= self.critical_threshold:
            return "Critical"
        elif score >= self.high_threshold:
            return "High"
        elif score >= self.medium_threshold:
            return "Medium"
        return "Low"

ueba_engine = UEBAEngine()
