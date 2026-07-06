"""DB-backed login sessions: create, validate, revoke."""
import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models.db_models import SessionDB, UserDB


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: UserDB) -> str:
    """Create a session for the user and return the raw token (never stored)."""
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    db.add(SessionDB(
        token_hash=_hash_token(token),
        user_id=user.id,
        username=user.username,
        role=user.role,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=settings.SESSION_TTL_HOURS)).isoformat(),
    ))
    db.commit()
    return token


def validate_token(db: Session, token: str | None) -> SessionDB | None:
    """Return the session if the token is valid and unexpired, else None."""
    if not token:
        return None
    session = db.query(SessionDB).filter(SessionDB.token_hash == _hash_token(token)).first()
    if not session:
        return None
    if session.expires_at < datetime.utcnow().isoformat():
        db.delete(session)
        db.commit()
        return None
    return session


def revoke(db: Session, token: str | None) -> str | None:
    """Delete the session for the token. Returns the username if one existed."""
    if not token:
        return None
    session = db.query(SessionDB).filter(SessionDB.token_hash == _hash_token(token)).first()
    if not session:
        return None
    username = session.username
    db.delete(session)
    db.commit()
    return username


def cleanup_expired(db: Session) -> int:
    """Remove expired sessions; returns how many were deleted."""
    now = datetime.utcnow().isoformat()
    count = db.query(SessionDB).filter(SessionDB.expires_at < now).delete()
    db.commit()
    return count
