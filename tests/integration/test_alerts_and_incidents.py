import json

import pytest


@pytest.fixture()
def seeded_alert():
    """Insert one normalized+scored alert into the app database."""
    from app.database import SessionLocal
    from app.models.db_models import NormalizedAlertDB, ScoredAlertDB

    raw_id = "pytest-alert-1"
    db = SessionLocal()
    try:
        if not db.query(NormalizedAlertDB).filter_by(raw_alert_id=raw_id).first():
            db.add(NormalizedAlertDB(
                raw_alert_id=raw_id,
                event_type="network_signature_alert",
                source_ip="203.0.113.77",
                category="ids",
                raw_severity=3,
                mitre_ids_json=json.dumps(["T1110"]),
                attack_type="Brute Force",
                normalized_payload_json="{}",
            ))
            db.add(ScoredAlertDB(
                raw_alert_id=raw_id,
                risk_score=85,
                score_reasons_json="[]",
                recommended_action="block_and_report",
                action_taken="none",
                processed_at="2026-01-01T00:00:00",
            ))
            db.commit()
    finally:
        db.close()
    return raw_id


def test_block_ip_requires_auth(client):
    client.cookies.clear()
    resp = client.post("/api/v1/alerts/block-ip", json={"ip": "203.0.113.10", "reason": "test"})
    assert resp.status_code == 401


def test_block_ip_authenticated(authed_client):
    resp = authed_client.post("/api/v1/alerts/block-ip", json={"ip": "203.0.113.10", "reason": "test"})
    assert resp.status_code == 200
    resp = authed_client.get("/blocked-ips")
    assert resp.status_code == 200


def test_create_incident_via_alerts_api(authed_client, seeded_alert):
    resp = authed_client.post(
        "/api/v1/alerts/create-incident",
        json={"raw_alert_id": seeded_alert, "title": "Manual incident from pytest"},
    )
    assert resp.status_code == 200
    incident_id = resp.json()["incident_id"]

    resp = authed_client.get("/api/v1/incidents/")
    assert resp.status_code == 200
    incidents = resp.json()
    assert any(i["id"] == incident_id for i in incidents)


def test_create_incident_unknown_alert_404(authed_client):
    resp = authed_client.post(
        "/api/v1/alerts/create-incident", json={"raw_alert_id": "does-not-exist"}
    )
    assert resp.status_code == 404


def test_incident_detail_and_sla(authed_client, seeded_alert):
    authed_client.post(
        "/api/v1/alerts/create-incident",
        json={"raw_alert_id": seeded_alert, "title": "SLA check incident"},
    )
    incidents = authed_client.get("/api/v1/incidents/").json()
    assert incidents
    assert "sla" in incidents[0]

    resp = authed_client.get(f"/api/v1/incidents/{incidents[0]['id']}")
    assert resp.status_code == 200


def test_api_key_roundtrip(authed_client):
    resp = authed_client.post("/api/v1/api-keys", json={"name": "pytest-key"})
    assert resp.status_code == 200
    body = resp.json()
    key, secret = body["key"], body["secret"]

    # The X-API-Key header alone must authenticate a protected endpoint
    authed_client.cookies.clear()
    resp = authed_client.get("/api/v1/incidents/", headers={"X-API-Key": f"{key}.{secret}"})
    assert resp.status_code == 200

    resp = authed_client.get("/api/v1/incidents/", headers={"X-API-Key": f"{key}.wrong"})
    assert resp.status_code == 401
