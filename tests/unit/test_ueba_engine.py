from types import SimpleNamespace

from app.models.db_models import IncidentDB, IPEntityProfileDB
from app.services.ueba_engine import UEBAEngine


def _alert(ip="10.0.0.9", risk=30, alert_id="a-1"):
    scored = SimpleNamespace(risk_score=risk, raw_alert_id=alert_id)
    normalized = SimpleNamespace(source_ip=ip)
    return scored, normalized


def test_profile_created_on_first_alert(db):
    engine = UEBAEngine()
    profile = engine.update_profile(db, *_alert(risk=20))
    assert profile.total_alerts_seen == 1
    assert profile.cumulative_risk_score == 20
    assert profile.risk_level == "Low"


def test_cumulative_risk_accumulates(db):
    engine = UEBAEngine()
    for i in range(3):
        profile = engine.update_profile(db, *_alert(risk=30, alert_id=f"a-{i}"))
    assert profile.total_alerts_seen == 3
    assert profile.cumulative_risk_score == 90
    assert profile.risk_level == "Medium"


def test_escalation_to_high_creates_incident(db):
    engine = UEBAEngine()
    engine.update_profile(db, *_alert(risk=60))
    assert db.query(IncidentDB).count() == 0

    engine.update_profile(db, *_alert(risk=60, alert_id="a-2"))  # cumulative 120 -> High
    profile = db.query(IPEntityProfileDB).one()
    assert profile.risk_level == "High"
    incidents = db.query(IncidentDB).all()
    assert len(incidents) == 1
    assert "UEBA" in incidents[0].title


def test_no_profile_without_source_ip(db):
    engine = UEBAEngine()
    assert engine.update_profile(db, *_alert(ip=None)) is None
