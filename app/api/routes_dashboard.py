from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import desc

from app.websockets import manager

from app.database import SessionLocal
from app.models.db_models import BlockedIPDB, EvaluationResultDB, RawAlertDB, ScoredAlertDB

router = APIRouter()
templates = Jinja2Templates(directory=str(Path("app/templates")))


@router.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    return templates.TemplateResponse("api_docs.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    token = request.cookies.get("session_token")
    if not token or not token.startswith("authenticated_"):
        return RedirectResponse(url="/login")
        
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
        import json
        for alert in raw_alerts:
            # We must handle both stringified JSON lists (from sqlite) and native lists
            try:
                payload = json.loads(alert.raw_payload_json) if isinstance(alert.raw_payload_json, str) else (alert.raw_payload_json or {})
                meta = payload.get("metadata", {})
                
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

        # Extract geo data for initial map plot
        # Extract geo data for initial map plot
        import sqlite3
        import os
        
        geo_cache = {}
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        db_path = os.path.join(base_dir, "data", "geoip_cache.db")
        
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address, lat, lon, country, city FROM geoip")
                geo_cache = {row[0]: {"lat": row[1], "lon": row[2], "country": row[3], "city": row[4]} for row in cursor.fetchall()}
                conn.close()
            except Exception:
                pass

        from app.models.db_models import NormalizedAlertDB
        
        # Get historical normalized alerts that have cached locations (for map visual flair)
        map_alerts = db.query(NormalizedAlertDB).filter(NormalizedAlertDB.source_ip.isnot(None)).order_by(desc(NormalizedAlertDB.id)).limit(1000).all()
        geo_scored_alerts = []
        
        for norm in map_alerts:
            if norm.source_ip in geo_cache:
                loc = geo_cache[norm.source_ip]
                if loc["lat"] and loc["lon"]:
                    geo_scored_alerts.append({
                        "lat": loc["lat"],
                        "lon": loc["lon"],
                        "country": loc["country"] or "Unknown",
                        "city": loc["city"] or "Unknown",
                        "risk_score": norm.raw_severity * 30 + 10 # approximate risk since scored DB might not have all limit overlap
                    })

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
                "geo_scored_alerts": geo_scored_alerts,
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
    lat: float | None = None
    lon: float | None = None
    country: str | None = None
    city: str | None = None
    is_anomaly: bool = False

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


class HuntQuery(BaseModel):
    query: str

@router.post("/api/hunt")
def hunt_threats(hunt: HuntQuery):
    """
    Experimental Active Threat Hunting Endpoint.
    Translates a simple string like 'mitre:T1110 risk:>80 action:block' into an advanced SQL query.
    """
    from sqlalchemy import or_, and_
    from app.models.db_models import ScoredAlertDB, NormalizedAlertDB, RawAlertDB
    from app.database import SessionLocal
    import re
    
    db = SessionLocal()
    try:
        query_str = hunt.query.lower().strip()
        
        # Base joins
        query = db.query(ScoredAlertDB, NormalizedAlertDB, RawAlertDB)\
                  .join(NormalizedAlertDB, ScoredAlertDB.raw_alert_id == NormalizedAlertDB.raw_alert_id)\
                  .join(RawAlertDB, ScoredAlertDB.raw_alert_id == RawAlertDB.id)

        filters = []

        # Parse 'risk:>80' or 'risk:90'
        risk_match = re.search(r'risk:([><=]?)(\d+)', query_str)
        if risk_match:
            op, val = risk_match.groups()
            val = int(val)
            if op == '>': filters.append(ScoredAlertDB.risk_score > val)
            elif op == '<': filters.append(ScoredAlertDB.risk_score < val)
            else: filters.append(ScoredAlertDB.risk_score == val)

        # Parse 'mitre:T1110'
        mitre_match = re.search(r'mitre:(t\d{4})', query_str)
        if mitre_match:
            ttp = mitre_match.group(1).upper()
            filters.append(NormalizedAlertDB.mitre_ids_json.like(f"%{ttp}%"))

        # Parse 'action:block'
        action_match = re.search(r'action:(\w+)', query_str)
        if action_match:
            actionStr = action_match.group(1)
            filters.append(ScoredAlertDB.recommended_action.like(f"%{actionStr}%"))

        # Parse 'ip:192.168.1.1'
        ip_match = re.search(r'ip:([\d\.]+)', query_str)
        if ip_match:
            ip = ip_match.group(1)
            filters.append(NormalizedAlertDB.source_ip == ip)

        # General keyword search in the raw message if no specific tags found
        if not filters and query_str:
            filters.append(RawAlertDB.message.ilike(f"%{query_str}%"))

        if filters:
            query = query.filter(and_(*filters))

        # Limit to 50 for performance
        results = query.order_by(ScoredAlertDB.id.desc()).limit(50).all()

        formatted_results = []
        for scored, norm, raw in results:
            formatted_results.append({
                "alert_id": raw.id,
                "timestamp": scored.processed_at,
                "risk_score": scored.risk_score,
                "action": scored.recommended_action,
                "source_ip": norm.source_ip,
                "message": raw.message
            })

        # Build timeline histogram
        from collections import defaultdict
        timeline = defaultdict(int)
        for r in formatted_results:
            try:
                # Group by minute for a clean chart
                minute = str(r["timestamp"])[:16] # e.g. "2026-04-13T22:08"
                timeline[minute] += 1
            except:
                pass
        
        timeline_sorted = [{"time": k, "count": v} for k, v in sorted(timeline.items())]

        return {"status": "success", "results": formatted_results, "timeline": timeline_sorted}
    finally:
        db.close()


@router.get("/api/v1/graph-data")
def get_attack_graph_data():
    from app.models.db_models import NormalizedAlertDB, ScoredAlertDB
    from app.database import SessionLocal
    from sqlalchemy import desc
    
    db = SessionLocal()
    try:
        # Fetch most recent critical/high alerts to make the graph interesting
        query = db.query(NormalizedAlertDB, ScoredAlertDB).join(ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id).filter(NormalizedAlertDB.source_ip.isnot(None)).order_by(desc(ScoredAlertDB.id)).limit(100).all()
        
        nodes = []
        edges = []
        
        # Central target node
        nodes.append({"data": {"id": "INTERNAL_NET", "label": "Internal Net", "type": "target"}})
        
        seen_ips = set()
        seen_edges = set()
        
        for norm, scored in query:
            ip = norm.source_ip
            if ip not in seen_ips:
                # Color code based on risk
                risk_class = "attacker-critical" if scored.risk_score >= 80 else "attacker-high" if scored.risk_score >= 60 else "attacker"
                nodes.append({"data": {"id": ip, "label": ip, "type": risk_class}})
                seen_ips.add(ip)
            
            edge_id = f"{ip}-{norm.event_type}"
            if edge_id not in seen_edges:
                edges.append({"data": {"id": edge_id, "source": ip, "target": "INTERNAL_NET", "label": norm.event_type}})
                seen_edges.add(edge_id)
                
        return {"nodes": nodes, "edges": edges}
    finally:
        db.close()