from fastapi import APIRouter, Depends, HTTPException, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from app.database import get_db
from app.services.auth_service import auth_service

router = APIRouter()
templates = Jinja2Templates(directory=str(Path("app/templates")))

@router.get("/login", response_class=HTMLResponse, tags=["Authentication"])
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login", tags=["Authentication"])
def login_submit(response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Simple hardcoded mock auth for the simulation if db is not setup or empty
    # In a real enterprise app, check auth_service.get_user_by_username and hash passwords
    if username in ["admin", "user.admin"] and password in ["admin", "password"]:
        resp = RedirectResponse(url="/dashboard", status_code=302)
        resp.set_cookie(key="session_token", value="authenticated_admin_token", httponly=True)
        return resp

    user = auth_service.get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Normally check password here
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie(key="session_token", value=f"authenticated_{username}", httponly=True)
    return resp

@router.get("/api/v1/auth/logout", tags=["Authentication"])
def logout():
    resp = RedirectResponse(url="/login")
    resp.delete_cookie("session_token")
    return resp

@router.post("/api/v1/auth/init", tags=["Authentication"])
def init_auth(db: Session = Depends(get_db)):
    auth_service.init_mock_users(db)
    return {"status": "Mock users initialized."}

@router.get("/api/v1/auth/users", tags=["Authentication"])
def get_users(db: Session = Depends(get_db)):
    return auth_service.get_all_users(db)

