def test_ioc_crud_via_api(authed_client):
    resp = authed_client.post(
        "/api/v1/ioc/",
        json={"ioc_type": "ip", "value": "192.0.2.55", "severity": "High", "source": "pytest"},
    )
    assert resp.status_code == 200

    resp = authed_client.get("/api/v1/ioc/")
    assert resp.status_code == 200
    body = resp.json()
    iocs = body.get("iocs", body) if isinstance(body, dict) else body
    assert any(i["value"] == "192.0.2.55" for i in iocs)

    resp = authed_client.get("/api/v1/ioc/check/192.0.2.55")
    assert resp.status_code == 200

    resp = authed_client.get("/api/v1/ioc/stats")
    assert resp.status_code == 200
    assert resp.json().get("total", 0) >= 1
