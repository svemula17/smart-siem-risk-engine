from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import BlockedIPDB, EvaluationResultDB, RawAlertDB, ScoredAlertDB

router = APIRouter()
templates = Jinja2Templates(directory=str(Path("app/templates")))


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    db = SessionLocal()
    try:
        raw_alerts = db.query(RawAlertDB).order_by(desc(RawAlertDB.created_at)).all()
        scored_alerts = db.query(ScoredAlertDB).order_by(desc(ScoredAlertDB.id)).all()
        blocked_ips = db.query(BlockedIPDB).order_by(desc(BlockedIPDB.id)).all()
        evaluation_results = db.query(EvaluationResultDB).all()

        total_alerts = len(evaluation_results)
        correct_band = sum(1 for r in evaluation_results if r.is_correct_band)
        correct_action = sum(1 for r in evaluation_results if r.is_correct_action)

        band_accuracy = round((correct_band / total_alerts) * 100, 2) if total_alerts else 0.0
        action_accuracy = round((correct_action / total_alerts) * 100, 2) if total_alerts else 0.0

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "raw_alert_count": len(raw_alerts),
                "scored_alert_count": len(scored_alerts),
                "blocked_ip_count": len(blocked_ips),
                "band_accuracy": band_accuracy,
                "action_accuracy": action_accuracy,
                "recent_scored_alerts": scored_alerts[:10],
                "recent_blocked_ips": blocked_ips[:10],
            },
        )
    finally:
        db.close()