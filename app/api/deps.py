"""Shared auth dependencies: session cookie or X-API-Key, plus role guards."""
import hashlib
from datetime import datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import APIKeyDB
from app.services import session_service


class AuthenticatedUser:
    def __init__(self, user_id: int, username: str, role: str, via: str):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.via = via  # "session" | "api_key"


def _auth_via_api_key(db: Session, header_value: str) -> AuthenticatedUser | None:
    """Validate 'X-API-Key: <key>.<secret>' against the api_keys table."""
    key, _, secret = header_value.partition(".")
    if not key or not secret:
        return None
    record = db.query(APIKeyDB).filter(APIKeyDB.key == key, APIKeyDB.is_active.is_(True)).first()
    if not record:
        return None
    if record.secret_hash != hashlib.sha256(secret.encode()).hexdigest():
        return None
    if record.expires_at and record.expires_at < datetime.utcnow().isoformat():
        return None
    record.last_used_at = datetime.utcnow().isoformat()
    db.commit()
    return AuthenticatedUser(user_id=record.user_id, username=f"api:{record.name}", role="Analyst", via="api_key")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> AuthenticatedUser:
    session = session_service.validate_token(db, request.cookies.get("session_token"))
    if session:
        return AuthenticatedUser(user_id=session.user_id, username=session.username, role=session.role, via="session")

    api_key = request.headers.get("X-API-Key")
    if api_key:
        user = _auth_via_api_key(db, api_key)
        if user:
            return user

    raise HTTPException(status_code=401, detail="Not authenticated")


def require_role(*roles: str):
    """Dependency factory: require the authenticated user to have one of the roles."""
    def checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {' or '.join(roles)}")
        return user
    return checker
