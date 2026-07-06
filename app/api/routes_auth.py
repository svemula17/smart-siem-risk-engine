from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedUser, require_role
from app.config import settings
from app.database import get_db
from app.security import rate_limiter
from app.services import session_service
from app.services.audit_logger import log_action
from app.services.auth_service import auth_service

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


class UserOut(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True


@router.get("/login", response_class=HTMLResponse, tags=["Authentication"])
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login", tags=["Authentication"])
def login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Authenticate user and issue a DB-backed session cookie."""
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(f"login:{client_ip}"):
        raise HTTPException(status_code=429, detail="Too many login attempts, slow down")

    user = auth_service.get_user_by_username(db, username)
    if not user or not auth_service.verify_password(password, user.password_hash):
        log_action(db, actor=username, action="login_attempt", target="auth", result="failure")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = session_service.create_session(db, user)
    log_action(db, actor=username, action="login", target="auth", result="success")

    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.SESSION_TTL_HOURS * 3600,
    )
    return resp


@router.get("/api/v1/auth/logout", tags=["Authentication"])
def logout(request: Request, db: Session = Depends(get_db)):
    """Logout user and revoke the session server-side."""
    username = session_service.revoke(db, request.cookies.get("session_token"))
    if username:
        log_action(db, actor=username, action="logout", target="auth", result="success")

    resp = RedirectResponse(url="/login")
    resp.delete_cookie("session_token")
    return resp


@router.get("/api/v1/auth/users", tags=["Authentication"], response_model=list[UserOut])
def get_users(
    db: Session = Depends(get_db),
    _admin: AuthenticatedUser = Depends(require_role("Admin")),
):
    """List all users (Admin only; never exposes password hashes)."""
    return auth_service.get_all_users(db)
