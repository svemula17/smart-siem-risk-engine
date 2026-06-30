"""API key management endpoints."""
from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import APIKeyDB, UserDB
from app.security import api_key_manager, _hash_secret
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api/v1/api-keys", tags=["API Keys"])


class APIKeyCreateRequest(BaseModel):
    name: str


class APIKeyResponse(BaseModel):
    key: str
    secret: str
    name: str
    created_at: str


class APIKeyListResponse(BaseModel):
    key: str
    name: str
    created_at: str
    last_used_at: str | None
    expires_at: str | None


@router.post("", response_model=APIKeyResponse)
def create_api_key(
    req: APIKeyCreateRequest, user_id: int = 1, db: Session = Depends(get_db)
):
    """Create a new API key. Secret is shown only once."""
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    key, secret = api_key_manager.generate_key(user_id, req.name)
    secret_hash = _hash_secret(secret)

    api_key = APIKeyDB(
        user_id=user_id,
        key=key,
        secret_hash=secret_hash,
        name=req.name,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(api_key)
    log_action(db, actor=user.username, action="create_api_key", target=key, detail=req.name)
    db.commit()

    return APIKeyResponse(key=key, secret=secret, name=req.name, created_at=api_key.created_at)


@router.get("", response_model=List[APIKeyListResponse])
def list_api_keys(user_id: int = 1, db: Session = Depends(get_db)):
    """List all API keys for the current user."""
    keys = db.query(APIKeyDB).filter(APIKeyDB.user_id == user_id).all()
    return [
        APIKeyListResponse(
            key=k.key,
            name=k.name,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
        )
        for k in keys
    ]


@router.delete("/{key}")
def revoke_api_key(key: str, user_id: int = 1, db: Session = Depends(get_db)):
    """Revoke an API key."""
    api_key = db.query(APIKeyDB).filter(APIKeyDB.key == key, APIKeyDB.user_id == user_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    db.delete(api_key)
    log_action(db, actor=user.username if user else "unknown", action="revoke_api_key", target=key)
    db.commit()

    return {"status": "revoked", "key": key}
