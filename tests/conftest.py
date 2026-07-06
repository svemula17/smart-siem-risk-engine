"""Shared fixtures. Environment must be configured BEFORE importing app.main,
which initializes the engine from settings at import time."""
import json
import os
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="siem-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/test.db")
os.environ.setdefault("DEMO_MODE", "0")
os.environ.setdefault("AUTO_PIPELINE", "0")
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("LOG_LEVEL", "WARNING")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def db():
    """Isolated in-memory database session for unit tests."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.database import Base

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    session = TestSession()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(scope="session")
def raw_alerts():
    """Twenty representative raw alerts (10 benign / 10 malicious) as Pydantic models."""
    from app.models.raw_alert import RawAlert

    data = json.loads((FIXTURES / "sample_alerts.json").read_text())
    return [RawAlert(**d) for d in data]


@pytest.fixture(scope="session")
def client():
    """TestClient against the real app (file-backed test DB, lifespan run)."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def authed_client(client):
    """Client logged in as the seeded admin (fresh login per test)."""
    client.cookies.clear()
    resp = client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-pass"},
        follow_redirects=False,
    )
    assert resp.status_code == 302, "admin login failed in fixture"
    client.cookies.set("session_token", resp.cookies["session_token"])
    return client
