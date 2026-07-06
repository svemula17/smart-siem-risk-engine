import pytest


@pytest.fixture()
def incident_id(authed_client):
    """Create an incident directly through the incident service in the app DB."""
    from app.database import SessionLocal
    from app.services.incident_service import create_incident

    db = SessionLocal()
    try:
        incident = create_incident(
            db, title="Case mgmt test incident", description="pytest",
            severity="High", alert_ids=["case-alert-1"],
        )
        return incident.id
    finally:
        db.close()


def test_comment_lifecycle(authed_client, incident_id):
    resp = authed_client.post(f"/api/v1/incidents/{incident_id}/comments", json={"body": "Looks like a brute force."})
    assert resp.status_code == 200

    resp = authed_client.get(f"/api/v1/incidents/{incident_id}/comments")
    comments = resp.json()["comments"]
    assert len(comments) == 1
    assert comments[0]["author"] == "admin"
    assert comments[0]["body"] == "Looks like a brute force."


def test_empty_comment_rejected(authed_client, incident_id):
    resp = authed_client.post(f"/api/v1/incidents/{incident_id}/comments", json={"body": "   "})
    assert resp.status_code == 422


def test_evidence_lifecycle(authed_client, incident_id):
    resp = authed_client.post(
        f"/api/v1/incidents/{incident_id}/evidence",
        json={"evidence_type": "ioc", "ref_id": "203.0.113.7", "description": "C2 address"},
    )
    assert resp.status_code == 200
    evidence_id = resp.json()["id"]

    resp = authed_client.get(f"/api/v1/incidents/{incident_id}/evidence")
    rows = resp.json()["evidence"]
    assert any(e["id"] == evidence_id and e["added_by"] == "admin" for e in rows)

    resp = authed_client.delete(f"/api/v1/incidents/{incident_id}/evidence/{evidence_id}")
    assert resp.status_code == 200
    rows = authed_client.get(f"/api/v1/incidents/{incident_id}/evidence").json()["evidence"]
    assert not any(e["id"] == evidence_id for e in rows)


def test_invalid_evidence_type_rejected(authed_client, incident_id):
    resp = authed_client.post(
        f"/api/v1/incidents/{incident_id}/evidence", json={"evidence_type": "screenshot"}
    )
    assert resp.status_code == 422


def test_case_detail_aggregates_everything(authed_client, incident_id):
    authed_client.post(f"/api/v1/incidents/{incident_id}/comments", json={"body": "note"})
    authed_client.post(f"/api/v1/incidents/{incident_id}/evidence", json={"evidence_type": "note", "description": "d"})

    resp = authed_client.get(f"/api/v1/incidents/{incident_id}/case")
    assert resp.status_code == 200
    case = resp.json()
    assert case["incident"]["id"] == incident_id
    assert case["sla"]["sla_status"] in ("ok", "warning", "breached", "met")
    assert len(case["comments"]) >= 1
    assert len(case["evidence"]) >= 1
    assert any("Comment added" in t["description"] for t in case["timeline"])
    assert any(t["actor"] == "admin" for t in case["timeline"])


def test_status_change_records_authenticated_actor(authed_client, incident_id):
    resp = authed_client.put(f"/api/v1/incidents/{incident_id}/status?status=In Progress")
    assert resp.status_code == 200

    case = authed_client.get(f"/api/v1/incidents/{incident_id}/case").json()
    assert case["incident"]["status"] == "In Progress"
    assert any("admin" in t["description"] for t in case["timeline"])


def test_case_endpoints_require_auth(client, incident_id):
    client.cookies.clear()
    assert client.get(f"/api/v1/incidents/{incident_id}/case").status_code == 401
    assert client.post(f"/api/v1/incidents/{incident_id}/comments", json={"body": "x"}).status_code == 401
