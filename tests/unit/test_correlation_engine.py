import json
from datetime import datetime

from app.models.db_models import CorrelationRuleDB, IncidentDB, NormalizedAlertDB, ScoredAlertDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.services.correlation_engine import CorrelationEngine


def _alert(mitre_ids, risk, alert_id="c-1", source_ip="203.0.113.5", attack_type="Unknown Threat"):
    norm = NormalizedAlert(
        alert_id=alert_id, source="test", group="NETWORK",
        event_type="network_signature_alert", title="t",
        source_ip=source_ip, start_time="0", end_time="0",
        raw_severity=3, category="ids", mitre_ids=mitre_ids,
        attack_type=attack_type, ground_truth_label="MALICIOUS",
    )
    scored = ScoredAlert(
        alert_id=alert_id, risk_score=risk, score_reasons=[],
        recommended_action="block_and_report", action_taken="none",
        processed_at=datetime.utcnow().isoformat(),
    )
    return scored, norm


def _persist(db, scored, norm):
    """Persist alert rows the way the pipeline does, so window queries see them."""
    db.add(NormalizedAlertDB(
        raw_alert_id=norm.alert_id, event_type=norm.event_type,
        source_ip=norm.source_ip, category=norm.category,
        raw_severity=norm.raw_severity, mitre_ids_json=json.dumps(norm.mitre_ids),
        attack_type=norm.attack_type, normalized_payload_json="{}",
    ))
    db.add(ScoredAlertDB(
        raw_alert_id=norm.alert_id, risk_score=scored.risk_score,
        score_reasons_json="[]", recommended_action=scored.recommended_action,
        action_taken="none", processed_at=scored.processed_at,
    ))
    db.commit()


def _seed_rule(db, mitre_id="T1110", min_risk=80):
    db.add(CorrelationRuleDB(
        name="Brute Force",
        description="test rule",
        logic_json=json.dumps({"type": "mitre_tactic", "mitre_id": mitre_id, "min_risk": min_risk}),
        severity="High",
        is_active=True,
    ))
    db.commit()


def test_matching_rule_creates_incident(db):
    _seed_rule(db)
    engine = CorrelationEngine()
    engine.evaluate_alert(db, *_alert(["T1110"], risk=90))
    assert db.query(IncidentDB).count() == 1


def test_low_risk_does_not_trigger(db):
    _seed_rule(db)
    engine = CorrelationEngine()
    engine.evaluate_alert(db, *_alert(["T1110"], risk=50))
    assert db.query(IncidentDB).count() == 0


def test_non_matching_mitre_does_not_trigger(db):
    _seed_rule(db)
    engine = CorrelationEngine()
    engine.evaluate_alert(db, *_alert(["T1566"], risk=95))
    assert db.query(IncidentDB).count() == 0


def test_inactive_rule_ignored(db):
    _seed_rule(db)
    rule = db.query(CorrelationRuleDB).one()
    rule.is_active = False
    db.commit()
    engine = CorrelationEngine()
    engine.evaluate_alert(db, *_alert(["T1110"], risk=90))
    assert db.query(IncidentDB).count() == 0


def _seed_typed_rule(db, name, logic, severity="High"):
    db.add(CorrelationRuleDB(
        name=name, description="t", logic_json=json.dumps(logic),
        severity=severity, is_active=True,
    ))
    db.commit()


def test_threshold_rule_fires_at_n_events(db):
    _seed_typed_rule(db, "BF Burst", {
        "type": "threshold", "attack_type": "Brute Force",
        "group_by": "source_ip", "threshold": 3, "window_minutes": 10,
    })
    engine = CorrelationEngine()

    for i in range(2):
        scored, norm = _alert([], 50, alert_id=f"t-{i}", attack_type="Brute Force")
        engine.evaluate_alert(db, scored, norm)
        _persist(db, scored, norm)
    assert db.query(IncidentDB).count() == 0  # below threshold

    scored, norm = _alert([], 50, alert_id="t-2", attack_type="Brute Force")
    engine.evaluate_alert(db, scored, norm)  # 2 persisted + this one = 3
    assert db.query(IncidentDB).count() == 1


def test_threshold_dedupe_appends_not_duplicates(db):
    _seed_typed_rule(db, "BF Burst", {
        "type": "threshold", "attack_type": "Brute Force",
        "group_by": "source_ip", "threshold": 2, "window_minutes": 10,
    })
    engine = CorrelationEngine()
    for i in range(4):
        scored, norm = _alert([], 50, alert_id=f"d-{i}", attack_type="Brute Force")
        engine.evaluate_alert(db, scored, norm)
        _persist(db, scored, norm)

    incidents = db.query(IncidentDB).all()
    assert len(incidents) == 1  # one incident, repeat matches appended
    assert len(json.loads(incidents[0].alerts_json)) >= 2


def test_sequence_rule(db):
    _seed_typed_rule(db, "Recon→Exfil", {
        "type": "sequence", "first": "Reconnaissance", "then": "Data Exfiltration",
        "group_by": "source_ip", "window_minutes": 60,
    }, severity="Critical")
    engine = CorrelationEngine()

    scored, norm = _alert([], 40, alert_id="s-1", attack_type="Reconnaissance")
    engine.evaluate_alert(db, scored, norm)
    _persist(db, scored, norm)
    assert db.query(IncidentDB).count() == 0

    scored, norm = _alert([], 70, alert_id="s-2", attack_type="Data Exfiltration")
    engine.evaluate_alert(db, scored, norm)
    incidents = db.query(IncidentDB).all()
    assert len(incidents) == 1
    assert incidents[0].severity == "Critical"


def test_sequence_requires_same_entity(db):
    _seed_typed_rule(db, "Recon→Exfil", {
        "type": "sequence", "first": "Reconnaissance", "then": "Data Exfiltration",
        "group_by": "source_ip", "window_minutes": 60,
    })
    engine = CorrelationEngine()
    scored, norm = _alert([], 40, alert_id="s-1", source_ip="10.0.0.1", attack_type="Reconnaissance")
    engine.evaluate_alert(db, scored, norm)
    _persist(db, scored, norm)

    scored, norm = _alert([], 70, alert_id="s-2", source_ip="10.0.0.2", attack_type="Data Exfiltration")
    engine.evaluate_alert(db, scored, norm)
    assert db.query(IncidentDB).count() == 0


def test_ioc_plus_rule(db):
    from app.services.ioc_manager import add_ioc
    _seed_typed_rule(db, "Known-Bad Active", {"type": "ioc_plus", "min_risk": 60})
    add_ioc(db, "ip", "203.0.113.5", severity="Critical", source="Test")
    engine = CorrelationEngine()

    engine.evaluate_alert(db, *_alert([], 50))  # below min_risk
    assert db.query(IncidentDB).count() == 0

    engine.evaluate_alert(db, *_alert([], 75))
    assert db.query(IncidentDB).count() == 1

    engine.evaluate_alert(db, *_alert([], 90, source_ip="198.51.100.1"))  # not IOC-listed
    assert db.query(IncidentDB).count() == 1
