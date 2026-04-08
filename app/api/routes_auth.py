from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.auth_service import auth_service

router = APIRouter(prefix="/api/v1/auth")

@router.post("/init")
def init_auth(db: Session = Depends(get_db)):
    auth_service.init_mock_users(db)
    return {"status": "Mock users initialized."}

@router.post("/login")
def login(username: str, db: Session = Depends(get_db)):
    user = auth_service.get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # In a real app we would use JWT, but here we'll just return user info mock token
    return {
        "access_token": f"mock_token_for_{username}",
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }

@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    return auth_service.get_all_users(db)
