from sqlalchemy.orm import Session

from app.models.db_models import BlockedIPDB


def save_blocked_ip(
    db: Session,
    ip_address: str,
    raw_alert_id: str,
    reason: str,
    is_simulated: bool = True,
) -> None:
    db_record = BlockedIPDB(
        ip_address=ip_address,
        raw_alert_id=raw_alert_id,
        reason=reason,
        is_simulated=is_simulated,
    )
    db.add(db_record)
    db.commit()