import json

from app.models.db_models import NormalizedAlertDB, ScoredAlertDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.services.ml_engine import MLEngine


def _seed_history(db, n=60):
    for i in range(n):
        db.add(NormalizedAlertDB(
            raw_alert_id=f"r-{i}",
            event_type="network_signature_alert",
            source_ip=f"10.0.0.{i % 250}",
            category="ids",
            raw_severity=(i % 3) + 1,
            mitre_ids_json=json.dumps(["T1110"] if i % 4 == 0 else []),
            attack_type="Brute Force",
            normalized_payload_json="{}",
        ))
        db.add(ScoredAlertDB(
            raw_alert_id=f"r-{i}",
            risk_score=20 + (i % 40),
            score_reasons_json="[]",
            recommended_action="store_only",
            action_taken="none",
            processed_at="2026-01-01T00:00:00",
        ))
    db.commit()


def _pydantic_alert(severity=2, mitre=None, risk=30):
    norm = NormalizedAlert(
        alert_id="x-1", source="test", group="NETWORK",
        event_type="network_signature_alert", title="t",
        start_time="0", end_time="0", raw_severity=severity,
        category="ids", mitre_ids=mitre or [], ground_truth_label="MALICIOUS",
    )
    scored = ScoredAlert(
        alert_id="x-1", risk_score=risk, score_reasons=[],
        recommended_action="store_only", action_taken="none",
        processed_at="2026-01-01T00:00:00",
    )
    return norm, scored


def test_untrained_engine_never_flags(tmp_path):
    engine = MLEngine(model_path=str(tmp_path / "m.pkl"))
    assert engine.is_trained is False
    assert engine.predict_anomaly(*_pydantic_alert()) is False


def test_training_requires_minimum_history(db, tmp_path):
    engine = MLEngine(model_path=str(tmp_path / "m.pkl"))
    _seed_history(db, n=10)
    engine.train_on_history(db)
    assert engine.is_trained is False


def test_train_and_predict(db, tmp_path):
    model_file = tmp_path / "m.pkl"
    engine = MLEngine(model_path=str(model_file))
    _seed_history(db)
    engine.train_on_history(db)
    assert engine.is_trained
    assert model_file.exists()

    # An extreme outlier must score at least as anomalous as a typical alert
    _, outlier_score = engine.predict_anomaly_with_score(*_pydantic_alert(severity=10, mitre=["T1", "T2", "T3", "T4", "T5"], risk=100))
    _, typical_score = engine.predict_anomaly_with_score(*_pydantic_alert(severity=2, risk=30))
    assert 0.0 <= typical_score <= outlier_score <= 1.0


def test_model_reloads_from_disk(db, tmp_path):
    model_file = tmp_path / "m.pkl"
    engine = MLEngine(model_path=str(model_file))
    _seed_history(db)
    engine.train_on_history(db)

    reloaded = MLEngine(model_path=str(model_file))
    assert reloaded.is_trained
