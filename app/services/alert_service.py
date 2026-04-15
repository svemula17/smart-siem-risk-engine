from datetime import datetime

from sqlalchemy.orm import Session

from app.models.db_models import NormalizedAlertDB, RawAlertDB, ScoredAlertDB
from app.models.normalized_alert import NormalizedAlert
from app.models.raw_alert import RawAlert
from app.models.scored_alert import ScoredAlert
from app.utils import to_json


def save_raw_alert(db: Session, raw_alert: RawAlert) -> None:
    existing = db.query(RawAlertDB).filter(RawAlertDB.id == raw_alert.id).first()
    if existing:
        return

    db_record = RawAlertDB(
        id=raw_alert.id,
        source=raw_alert.source,
        group_name=raw_alert.group,
        type=raw_alert.type,
        message=raw_alert.message,
        raw_payload_json=to_json(raw_alert.model_dump()),
        ground_truth_label=raw_alert.ground_truth_label,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(db_record)
    db.commit()


def save_normalized_alert(db: Session, normalized_alert: NormalizedAlert) -> None:
    db_record = NormalizedAlertDB(
        raw_alert_id=normalized_alert.alert_id,
        event_type=normalized_alert.event_type,
        source_ip=normalized_alert.source_ip,
        category=normalized_alert.category,
        raw_severity=normalized_alert.raw_severity,
        signature=normalized_alert.signature,
        mitre_ids_json=to_json(normalized_alert.mitre_ids),
        attack_type=normalized_alert.attack_type,
        normalized_payload_json=to_json(normalized_alert.model_dump()),
    )
    db.add(db_record)
    db.commit()


def save_scored_alert(db: Session, scored_alert: ScoredAlert) -> None:
    db_record = ScoredAlertDB(
        raw_alert_id=scored_alert.alert_id,
        risk_score=scored_alert.risk_score,
        score_reasons_json=to_json(scored_alert.score_reasons),
        recommended_action=scored_alert.recommended_action,
        action_taken=scored_alert.action_taken,
        processed_at=scored_alert.processed_at,
    )
    db.add(db_record)
    db.commit()