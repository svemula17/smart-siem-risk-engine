import json

from app.models.db_models import CorrelationRuleDB, IncidentDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.services.correlation_engine import CorrelationEngine


def _alert(mitre_ids, risk):
    norm = NormalizedAlert(
        alert_id="c-1", source="test", group="NETWORK",
        event_type="network_signature_alert", title="t",
        source_ip="203.0.113.5", start_time="0", end_time="0",
        raw_severity=3, category="ids", mitre_ids=mitre_ids,
        ground_truth_label="MALICIOUS",
    )
    scored = ScoredAlert(
        alert_id="c-1", risk_score=risk, score_reasons=[],
        recommended_action="block_and_report", action_taken="none",
        processed_at="2026-01-01T00:00:00",
    )
    return scored, norm


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
