import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from app.database import get_db
from app.services.auth_service import auth_service
from app.services.audit_logger import log_action

router = APIRouter()
templates = Jinja2Templates(directory=str(Path("app/templates")))

SESSION_TOKENS = {}

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)

@router.get("/login", response_class=HTMLResponse, tags=["Authentication"])
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login", tags=["Authentication"])
def login_submit(response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """Authenticate user with password verification."""
    user = auth_service.get_user_by_username(db, username)
    if not user or not auth_service.verify_password(password, user.password_hash):
        log_action(db, actor=username, action="login_attempt", target="auth", result="failure")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = generate_session_token()
    SESSION_TOKENS[token] = {"username": username, "user_id": user.id, "role": user.role}
    log_action(db, actor=username, action="login", target="auth", result="success")

    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie(key="session_token", value=token, httponly=True, secure=False, samesite="lax")
    return resp

@router.get("/api/v1/auth/logout", tags=["Authentication"])
def logout(request: Request, db: Session = Depends(get_db)):
    """Logout user and invalidate session."""
    token = request.cookies.get("session_token")
    if token and token in SESSION_TOKENS:
        session_data = SESSION_TOKENS.pop(token)
        log_action(db, actor=session_data.get("username", "unknown"), action="logout", target="auth", result="success")

    resp = RedirectResponse(url="/login")
    resp.delete_cookie("session_token")
    return resp

@router.post("/api/v1/auth/init", tags=["Authentication"])
def init_auth(db: Session = Depends(get_db)):
    """Initialize mock users."""
    auth_service.init_mock_users(db)
    return {"status": "Mock users initialized."}

@router.get("/api/v1/auth/users", tags=["Authentication"])
def get_users(db: Session = Depends(get_db)):
    """List all users."""
    return auth_service.get_all_users(db)

