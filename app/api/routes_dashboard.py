import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import desc, func

from app.database import SessionLocal
from app.models.db_models import (
    BlockedIPDB,
    EvaluationResultDB,
    NormalizedAlertDB,
    RawAlertDB,
    ScoredAlertDB,
    SuppressedAlertDB,
)
from app.websockets import manager

router = APIRouter()
templates = Jinja2Templates(directory=str(Path("app/templates")))


@router.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    return templates.TemplateResponse("api_docs.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, replay: int = 1):
    token = request.cookies.get("session_token")
    if not token or not token.startswith("authenticated_"):
        return RedirectResponse(url="/login")

    # ── Replay-on-refresh: every dashboard GET triggers a fresh pipeline run
    #    so alerts stream in one-by-one via WebSocket. Disable with ?replay=0.
    if replay:
        try:
            from app import main as _app_main
            from app.models.db_models import (
                IncidentDB, IncidentTimelineDB, IPEntityProfileDB,
                AlertGroupDB, SuppressedAlertDB,
            )
            _app_main.stop_pipeline()
            _db = SessionLocal()
            try:
                _db.query(NormalizedAlertDB).delete()
                _db.query(ScoredAlertDB).delete()
                _db.query(EvaluationResultDB).delete()
                _db.query(BlockedIPDB).delete()
                _db.query(RawAlertDB).delete()
                _db.query(IncidentTimelineDB).delete()
                _db.query(IncidentDB).delete()
                _db.query(IPEntityProfileDB).delete()
                _db.query(AlertGroupDB).delete()
                _db.query(SuppressedAlertDB).delete()
                _db.commit()
            finally:
                _db.close()
            _app_main.launch_pipeline()
        except Exception as e:
            print(f"[dashboard] replay trigger failed: {e}")

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

        # Risk distribution
        risk_distribution = {
            "critical": sum(1 for a in scored_alerts if a.risk_score >= 80),
            "high": sum(1 for a in scored_alerts if 60 <= a.risk_score < 80),
            "medium": sum(1 for a in scored_alerts if 30 <= a.risk_score < 60),
            "low": sum(1 for a in scored_alerts if a.risk_score < 30),
        }

        # Attack type distribution (from NormalizedAlertDB)
        attack_type_rows = (
            db.query(NormalizedAlertDB.attack_type, func.count(NormalizedAlertDB.id).label("cnt"))
            .group_by(NormalizedAlertDB.attack_type)
            .order_by(func.count(NormalizedAlertDB.id).desc())
            .limit(10)
            .all()
        )
        attack_type_dist = {row[0] or "Unknown Threat": row[1] for row in attack_type_rows}

        # Active MITRE ATT&CK TTPs
        active_mitre_ids = set()
        for alert in raw_alerts[:5000]:  # limit scan for performance
            try:
                payload = json.loads(alert.raw_payload_json) if isinstance(alert.raw_payload_json, str) else {}
                logs = payload.get("metadata", {}).get("suricata_logs", [])
                for log in logs:
                    for m_id in (log.get("mitre_ids") or []):
                        if m_id:
                            active_mitre_ids.add(m_id)
            except Exception:
                pass

        # Fatigue metrics
        total_suppressed = db.query(func.count(SuppressedAlertDB.id)).scalar() or 0
        total_processed = len(scored_alerts)
        suppression_rate = round(
            (total_suppressed / max(total_processed + total_suppressed, 1)) * 100, 1
        )

        # Geo data
        geo_cache = {}
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        db_path = os.path.join(base_dir, "data", "geoip_cache.db")
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address, lat, lon, country, city FROM geoip")
                geo_cache = {
                    row[0]: {"lat": row[1], "lon": row[2], "country": row[3], "city": row[4]}
                    for row in cursor.fetchall()
                }
                conn.close()
            except Exception:
                pass

        map_alerts = (
            db.query(NormalizedAlertDB)
            .filter(NormalizedAlertDB.source_ip.isnot(None))
            .order_by(desc(NormalizedAlertDB.id))
            .limit(1000)
            .all()
        )
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
                        "risk_score": norm.raw_severity * 30 + 10,
                        "attack_type": norm.attack_type or "Unknown Threat",
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
                "attack_type_dist": attack_type_dist,
                "active_mitre_ids": list(active_mitre_ids),
                "geo_scored_alerts": geo_scored_alerts,
                "suppression_rate": suppression_rate,
                "total_suppressed": total_suppressed,
                "attack_type_count": len(attack_type_dist),
            },
        )
    finally:
        db.close()


# ── WebSocket broadcast ────────────────────────────────────────────────────────

class BroadcastData(BaseModel):
    alert_html: str
    risk_score: int
    recommended_action: str
    action_taken: str
    mitre_ids: list[str] = []
    attack_type: str = "Unknown Threat"
    lat: float | None = None
    lon: float | None = None
    country: str | None = None
    city: str | None = None
    is_anomaly: bool = False


@router.post("/api/internal/broadcast")
async def broadcast_alert(data: dict):
    await manager.broadcast(data)
    return {"status": "broadcasted"}


@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── IP block/unblock ──────────────────────────────────────────────────────────

class IPAction(BaseModel):
    ip_address: str
    reason: str = "Manual Override from Dashboard"


@router.post("/api/unblock_ip")
def unblock_ip(action: IPAction):
    db = SessionLocal()
    try:
        blocked = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == action.ip_address).first()
        if blocked:
            db.delete(blocked)
            db.commit()
            return {"status": "success", "message": f"IP {action.ip_address} unblocked."}
        raise HTTPException(status_code=404, detail="IP not found in Block List")
    finally:
        db.close()


@router.post("/api/block_ip")
def block_ip(action: IPAction):
    db = SessionLocal()
    try:
        existing = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == action.ip_address).first()
        if not existing:
            db.add(BlockedIPDB(ip_address=action.ip_address, reason=action.reason))
            db.commit()
        return {"status": "success", "message": f"IP {action.ip_address} blocked."}
    finally:
        db.close()


# ── Threat Hunting ────────────────────────────────────────────────────────────

class HuntQuery(BaseModel):
    query: str


@router.post("/api/hunt")
def hunt_threats(hunt: HuntQuery):
    from sqlalchemy import and_

    db = SessionLocal()
    try:
        query_str = hunt.query.lower().strip()
        query = (
            db.query(ScoredAlertDB, NormalizedAlertDB, RawAlertDB)
            .join(NormalizedAlertDB, ScoredAlertDB.raw_alert_id == NormalizedAlertDB.raw_alert_id)
            .join(RawAlertDB, ScoredAlertDB.raw_alert_id == RawAlertDB.id)
        )

        filters = []

        risk_match = re.search(r"risk:([><=]?)(\d+)", query_str)
        if risk_match:
            op, val = risk_match.groups()
            val = int(val)
            if op == ">":
                filters.append(ScoredAlertDB.risk_score > val)
            elif op == "<":
                filters.append(ScoredAlertDB.risk_score < val)
            else:
                filters.append(ScoredAlertDB.risk_score == val)

        mitre_match = re.search(r"mitre:(t\d{4})", query_str)
        if mitre_match:
            ttp = mitre_match.group(1).upper()
            filters.append(NormalizedAlertDB.mitre_ids_json.like(f"%{ttp}%"))

        action_match = re.search(r"action:(\w+)", query_str)
        if action_match:
            filters.append(ScoredAlertDB.recommended_action.like(f"%{action_match.group(1)}%"))

        ip_match = re.search(r"ip:([\d\.]+)", query_str)
        if ip_match:
            filters.append(NormalizedAlertDB.source_ip == ip_match.group(1))

        attack_match = re.search(r'attack:"?([^"\s]+)"?', query_str)
        if attack_match:
            filters.append(NormalizedAlertDB.attack_type.ilike(f"%{attack_match.group(1)}%"))

        if not filters and query_str:
            filters.append(RawAlertDB.message.ilike(f"%{query_str}%"))

        if filters:
            query = query.filter(and_(*filters))

        results = query.order_by(ScoredAlertDB.id.desc()).limit(50).all()

        formatted_results = []
        for scored, norm, raw in results:
            formatted_results.append({
                "alert_id": raw.id,
                "timestamp": scored.processed_at,
                "risk_score": scored.risk_score,
                "action": scored.recommended_action,
                "source_ip": norm.source_ip,
                "attack_type": norm.attack_type or "Unknown Threat",
                "message": raw.message,
            })

        timeline: dict = defaultdict(int)
        for r in formatted_results:
            minute = str(r["timestamp"])[:16]
            timeline[minute] += 1

        return {
            "status": "success",
            "results": formatted_results,
            "timeline": [{"time": k, "count": v} for k, v in sorted(timeline.items())],
        }
    finally:
        db.close()


# ── Attack Graph ──────────────────────────────────────────────────────────────

@router.get("/api/v1/graph-data")
def get_attack_graph_data():
    db = SessionLocal()
    try:
        query = (
            db.query(NormalizedAlertDB, ScoredAlertDB)
            .join(ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id)
            .filter(NormalizedAlertDB.source_ip.isnot(None))
            .order_by(desc(ScoredAlertDB.id))
            .limit(100)
            .all()
        )

        nodes = [{"data": {"id": "INTERNAL_NET", "label": "Internal Net", "type": "target"}}]
        edges = []
        seen_ips: set = set()
        seen_edges: set = set()

        for norm, scored in query:
            ip = norm.source_ip
            if ip not in seen_ips:
                risk_class = (
                    "attacker-critical" if scored.risk_score >= 80
                    else "attacker-high" if scored.risk_score >= 60
                    else "attacker"
                )
                nodes.append({
                    "data": {
                        "id": ip,
                        "label": ip,
                        "type": risk_class,
                        "attack_type": norm.attack_type or "Unknown",
                    }
                })
                seen_ips.add(ip)

            edge_id = f"{ip}-{norm.event_type}"
            if edge_id not in seen_edges:
                edges.append({
                    "data": {
                        "id": edge_id,
                        "source": ip,
                        "target": "INTERNAL_NET",
                        "label": norm.attack_type or norm.event_type,
                    }
                })
                seen_edges.add(edge_id)

        return {"nodes": nodes, "edges": edges}
    finally:
        db.close()


# ── NEW: Attack Type Stats ────────────────────────────────────────────────────

@router.get("/api/attack-type-stats")
def get_attack_type_stats():
    """Returns attack type distribution with risk breakdown."""
    db = SessionLocal()
    try:
        rows = (
            db.query(
                NormalizedAlertDB.attack_type,
                func.count(NormalizedAlertDB.id).label("total"),
            )
            .group_by(NormalizedAlertDB.attack_type)
            .order_by(func.count(NormalizedAlertDB.id).desc())
            .limit(15)
            .all()
        )

        result = []
        for attack_type, total in rows:
            result.append({
                "attack_type": attack_type or "Unknown Threat",
                "count": total,
            })

        return {"attack_types": result}
    finally:
        db.close()


# ── NEW: Alert Fatigue Metrics ────────────────────────────────────────────────

@router.get("/api/fatigue-metrics")
def get_fatigue_metrics():
    """Returns alert fatigue / suppression metrics."""
    from app.services.alert_deduplicator import get_fatigue_metrics as _get_metrics

    db = SessionLocal()
    try:
        return _get_metrics(db)
    finally:
        db.close()


# ── NEW: 7-day Alert Trend ───────────────────────────────────────────────────

@router.get("/api/alert-trends")
def get_alert_trends():
    """Returns 7-day alert counts grouped by day."""
    db = SessionLocal()
    try:
        rows = (
            db.query(ScoredAlertDB.processed_at, ScoredAlertDB.risk_score, ScoredAlertDB.recommended_action)
            .order_by(desc(ScoredAlertDB.id))
            .limit(50000)
            .all()
        )

        daily: dict = defaultdict(lambda: {"total": 0, "critical": 0, "blocked": 0})
        for processed_at, risk_score, action in rows:
            try:
                day = str(processed_at)[:10]
                daily[day]["total"] += 1
                if risk_score >= 80:
                    daily[day]["critical"] += 1
                if "block" in (action or "").lower():
                    daily[day]["blocked"] += 1
            except Exception:
                pass

        sorted_days = sorted(daily.keys())[-7:]
        trend = [
            {
                "day": d,
                "total": daily[d]["total"],
                "critical": daily[d]["critical"],
                "blocked": daily[d]["blocked"],
            }
            for d in sorted_days
        ]
        return {"trend": trend}
    finally:
        db.close()


# ── NEW: MITRE Heatmap ───────────────────────────────────────────────────────

@router.get("/api/mitre-heatmap")
def get_mitre_heatmap():
    """Returns MITRE TTP counts for heatmap visualization."""
    db = SessionLocal()
    try:
        rows = (
            db.query(NormalizedAlertDB.mitre_ids_json, NormalizedAlertDB.attack_type)
            .filter(NormalizedAlertDB.mitre_ids_json.isnot(None))
            .limit(20000)
            .all()
        )

        ttp_counts: dict = defaultdict(int)
        for mitre_json, _ in rows:
            try:
                ids = json.loads(mitre_json) if mitre_json else []
                for mid in ids:
                    if mid and mid not in ("None", "Duplicate"):
                        ttp_counts[mid] += 1
            except Exception:
                pass

        sorted_ttps = sorted(ttp_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        return {
            "ttps": [{"id": k, "count": v} for k, v in sorted_ttps]
        }
    finally:
        db.close()


# ── NEW: ML Cluster Summary ──────────────────────────────────────────────────

@router.get("/api/alert-clusters")
def get_alert_clusters():
    """Returns DBSCAN cluster summary for alert grouping view."""
    from app.services.alert_deduplicator import cluster_alerts_by_similarity

    db = SessionLocal()
    try:
        clusters = cluster_alerts_by_similarity(db, limit=2000)
        return {"clusters": list(clusters.values())}
    finally:
        db.close()
