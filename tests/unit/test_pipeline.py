from app.models.db_models import (
    EvaluationResultDB,
    IPEntityProfileDB,
    NormalizedAlertDB,
    RawAlertDB,
    ScoredAlertDB,
)
from app.services.pipeline import build_broadcast_payload, process_raw_alert


def test_pipeline_persists_full_chain(db, raw_alerts):
    alert = raw_alerts[0]
    scored, evaluation = process_raw_alert(db, alert)

    assert 0 <= scored.risk_score <= 100
    assert db.query(RawAlertDB).filter_by(id=alert.id).one()
    assert db.query(NormalizedAlertDB).filter_by(raw_alert_id=alert.id).one()
    assert db.query(ScoredAlertDB).filter_by(raw_alert_id=alert.id).one()
    assert db.query(EvaluationResultDB).filter_by(raw_alert_id=alert.id).one()


def test_pipeline_updates_ueba(db, raw_alerts):
    with_ip = next(a for a in raw_alerts if a.entity_ids.ip)
    process_raw_alert(db, with_ip)
    profile = db.query(IPEntityProfileDB).filter_by(ip_address=with_ip.entity_ids.ip[0]).first()
    assert profile is not None
    assert profile.total_alerts_seen == 1


def test_pipeline_notify_callback_receives_payload(db, raw_alerts):
    received = []
    process_raw_alert(db, raw_alerts[1], notify=received.append)
    assert len(received) == 1
    payload = received[0]
    assert {"alert_html", "risk_score", "recommended_action", "is_anomaly"} <= payload.keys()


def test_pipeline_survives_broken_notify(db, raw_alerts):
    def boom(_payload):
        raise RuntimeError("dashboard down")
    scored, _ = process_raw_alert(db, raw_alerts[2], notify=boom)
    assert scored is not None  # ingestion never stalls on broadcast errors


def test_broadcast_payload_shape(db, raw_alerts):
    from app.normalization.mapper import normalize_alert
    from app.scoring.scorer import score_alert
    alert = raw_alerts[0]
    norm = normalize_alert(alert)
    scored = score_alert(norm)
    payload = build_broadcast_payload(alert, norm, scored, is_anomaly=False)
    assert payload["risk_score"] == scored.risk_score
    assert payload["is_anomaly"] is False
