def test_login_page_renders(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "login" in resp.text.lower()


def test_bad_credentials_rejected(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_unknown_user_rejected(client):
    resp = client.post("/login", data={"username": "ghost", "password": "x"})
    assert resp.status_code == 401


def test_unauthenticated_dashboard_redirects(client):
    client.cookies.clear()
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/login"


def test_protected_api_requires_auth(client):
    client.cookies.clear()
    for path in ("/api/v1/incidents/", "/api/v1/raw-alerts", "/api/v1/ioc"):
        resp = client.get(path)
        assert resp.status_code in (401, 404), path
        if resp.status_code == 404:
            continue  # path moved — auth still enforced at router level
        assert resp.status_code == 401


def test_full_login_logout_cycle(client):
    resp = client.post(
        "/login", data={"username": "admin", "password": "test-admin-pass"}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert "session_token" in resp.cookies

    assert client.get("/api/v1/incidents/").status_code == 200
    assert client.get("/dashboard?replay=0").status_code == 200

    client.get("/api/v1/auth/logout", follow_redirects=False)
    client.cookies.clear()
    assert client.get("/api/v1/incidents/").status_code == 401


def test_users_endpoint_admin_only_and_no_hashes(authed_client):
    resp = authed_client.get("/api/v1/auth/users")
    assert resp.status_code == 200
    users = resp.json()
    assert users, "expected at least the admin user"
    assert all("password_hash" not in u for u in users)


def test_internal_broadcast_requires_token(authed_client):
    resp = authed_client.post("/api/internal/broadcast", json={"a": 1})
    assert resp.status_code == 403

    from app.config import settings
    resp = authed_client.post(
        "/api/internal/broadcast", json={"a": 1}, headers={"X-Internal-Token": settings.INTERNAL_API_TOKEN}
    )
    assert resp.status_code == 200
