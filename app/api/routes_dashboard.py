from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import desc

from app.websockets import manager

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

        # Calculate risk distribution for the chart
        risk_distribution = {
            "critical": sum(1 for a in scored_alerts if a.risk_score >= 80),
            "high": sum(1 for a in scored_alerts if 60 <= a.risk_score < 80),
            "medium": sum(1 for a in scored_alerts if 30 <= a.risk_score < 60),
            "low": sum(1 for a in scored_alerts if a.risk_score < 30),
        }

        # Aggregate Active MITRE ATT&CK TTPs
        active_mitre_ids = set()
        for alert in raw_alerts:
            # We must handle both stringified JSON lists (from sqlite) and native lists
            import json
            try:
                if isinstance(alert.metadata_json, str):
                    meta = json.loads(alert.metadata_json)
                else:
                    meta = alert.metadata_json or {}
                
                # Check suricata logs for mitre ids
                logs = meta.get("suricata_logs", [])
                for log in logs:
                    mitre_list = log.get("mitre_ids", [])
                    if isinstance(mitre_list, list):
                        for m_id in mitre_list:
                            if m_id:
                                active_mitre_ids.add(m_id)
            except Exception:
                pass

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
                "risk_distribution": risk_distribution,
                "active_mitre_ids": list(active_mitre_ids),
            },
        )
    finally:
        db.close()


class BroadcastData(BaseModel):
    alert_html: str
    risk_score: int
    recommended_action: str
    action_taken: str
    mitre_ids: list[str] = []

@router.post("/api/internal/broadcast")
async def broadcast_alert(data: dict):
    # Receives data from run.py and broadcasts it to all connected websocket clients
    await manager.broadcast(data)
    return {"status": "broadcasted"}

@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, wait for messages if any (mostly one-way from server to client)
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


class IPAction(BaseModel):
    ip_address: str
    reason: str = "Manual Override from Dashboard"


@router.post("/api/unblock_ip")
def unblock_ip(action: IPAction):
    db = SessionLocal()
    try:
        # Find and delete the block record
        blocked = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == action.ip_address).first()
        if blocked:
            db.delete(blocked)
            db.commit()
            return {"status": "success", "message": f"IP {action.ip_address} unblocked."}
        else:
            raise HTTPException(status_code=404, detail="IP not found in Block List")
    finally:
        db.close()


@router.post("/api/block_ip")
def block_ip(action: IPAction):
    db = SessionLocal()
    try:
        # Check if already blocked
        existing = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == action.ip_address).first()
        if not existing:
            new_block = BlockedIPDB(ip_address=action.ip_address, reason=action.reason)
            db.add(new_block)
            db.commit()
        return {"status": "success", "message": f"IP {action.ip_address} blocked."}
    finally:
        db.close()