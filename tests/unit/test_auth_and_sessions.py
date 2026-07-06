from app.models.db_models import SessionDB, UserDB
from app.services import session_service
from app.services.auth_service import AuthService


def _make_user(db, username="alice", role="Analyst", password="s3cret!"):
    svc = AuthService()
    user = UserDB(username=username, password_hash=svc.hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_password_hash_roundtrip():
    svc = AuthService()
    h = svc.hash_password("hunter2")
    assert svc.verify_password("hunter2", h)
    assert not svc.verify_password("hunter3", h)
    assert "hunter2" not in h


def test_hashes_are_salted():
    svc = AuthService()
    assert svc.hash_password("same") != svc.hash_password("same")


def test_ensure_admin_uses_env_password(db, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "from-env-pw")
    svc = AuthService()
    svc.ensure_admin_user(db)
    admin = db.query(UserDB).filter(UserDB.username == "admin").first()
    assert admin is not None and admin.role == "Admin"
    assert svc.verify_password("from-env-pw", admin.password_hash)
    # idempotent: second call must not create another user
    svc.mock_users_created = False
    svc.ensure_admin_user(db)
    assert db.query(UserDB).count() == 1


def test_session_create_validate_revoke(db):
    user = _make_user(db)
    token = session_service.create_session(db, user)

    stored = db.query(SessionDB).one()
    assert stored.token_hash != token  # raw token never stored

    session = session_service.validate_token(db, token)
    assert session is not None and session.username == "alice"

    assert session_service.validate_token(db, "bogus") is None
    assert session_service.validate_token(db, None) is None

    assert session_service.revoke(db, token) == "alice"
    assert session_service.validate_token(db, token) is None


def test_expired_session_rejected_and_cleaned(db, monkeypatch):
    from app.config import settings
    user = _make_user(db, username="bob")
    monkeypatch.setattr(settings, "SESSION_TTL_HOURS", -1)
    token = session_service.create_session(db, user)
    assert session_service.validate_token(db, token) is None
    assert db.query(SessionDB).count() == 0
