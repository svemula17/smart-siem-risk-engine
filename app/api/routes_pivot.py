"""Pivot search — given an entity (IP/user/host/alert), return all related artifacts."""
import json

from fastapi import APIRouter, HTTPException
from sqlalchemy import desc

from app.database import SessionLocal
from app.models.db_models import (
    IOCDB,
    BlockedIPDB,
    IncidentDB,
    IPEntityProfileDB,
    NormalizedAlertDB,
    ScoredAlertDB,
)

router = APIRouter()


@router.get("/api/v1/pivot/{entity_type}/{value}")
def pivot(entity_type: str, value: str, limit: int = 100):
    """Return related artifacts for an entity. Supported types: ip, alert, host."""
    if entity_type not in ("ip", "alert", "host"):
        raise HTTPException(status_code=400, detail="entity_type must be ip|alert|host")

    db = SessionLocal()
    try:
        result = {
            "entity_type": entity_type,
            "value": value,
            "alerts": [],
            "incidents": [],
            "iocs": [],
            "blocked": [],
            "ueba": None,
            "summary": {},
        }

        # Find normalized alerts referencing this entity
        if entity_type == "ip":
            norm_q = db.query(NormalizedAlertDB).filter(NormalizedAlertDB.source_ip == value)
        elif entity_type == "alert":
            norm_q = db.query(NormalizedAlertDB).filter(NormalizedAlertDB.raw_alert_id == value)
        else:  # host — match against payload JSON best-effort
            norm_q = db.query(NormalizedAlertDB).filter(
                NormalizedAlertDB.normalized_payload_json.like(f'%"{value}"%')
            )

        norm_rows = norm_q.order_by(desc(NormalizedAlertDB.id)).limit(limit).all()
        raw_alert_ids = [n.raw_alert_id for n in norm_rows]

        # Pull scored alerts in one query
        scored_map: dict = {}
        if raw_alert_ids:
            scored_rows = db.query(ScoredAlertDB).filter(
                ScoredAlertDB.raw_alert_id.in_(raw_alert_ids)
            ).all()
            scored_map = {s.raw_alert_id: s for s in scored_rows}

        attack_counter: dict = {}
        max_risk = 0
        for n in norm_rows:
            s = scored_map.get(n.raw_alert_id)
            risk = s.risk_score if s else 0
            max_risk = max(max_risk, risk)
            atk = n.attack_type or "Unknown"
            attack_counter[atk] = attack_counter.get(atk, 0) + 1
            result["alerts"].append({
                "raw_alert_id": n.raw_alert_id,
                "attack_type": atk,
                "source_ip": n.source_ip,
                "event_type": n.event_type,
                "category": n.category,
                "signature": n.signature,
                "risk_score": risk,
                "recommended_action": s.recommended_action if s else None,
                "processed_at": s.processed_at if s else None,
            })

        # Linked incidents (search alerts_json for any of these IDs)
        if raw_alert_ids:
            incidents = db.query(IncidentDB).order_by(desc(IncidentDB.created_at)).limit(200).all()
            for inc in incidents:
                try:
                    inc_alerts = json.loads(inc.alerts_json or "[]")
                except Exception:
                    inc_alerts = []
                if any(a in inc_alerts for a in raw_alert_ids):
                    result["incidents"].append({
                        "id": inc.id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "status": inc.status,
                        "created_at": inc.created_at,
                    })

        # IOCs and Blocked
        if entity_type == "ip":
            iocs = db.query(IOCDB).filter(IOCDB.value == value).all()
            result["iocs"] = [
                {"type": i.ioc_type, "severity": i.severity, "source": i.source,
                 "description": i.description, "is_active": i.is_active}
                for i in iocs
            ]
            blocked = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == value).all()
            result["blocked"] = [
                {"reason": b.reason, "raw_alert_id": b.raw_alert_id, "is_simulated": b.is_simulated}
                for b in blocked
            ]
            ueba = db.query(IPEntityProfileDB).filter(IPEntityProfileDB.ip_address == value).first()
            if ueba:
                result["ueba"] = {
                    "risk_level": ueba.risk_level,
                    "total_alerts_seen": ueba.total_alerts_seen,
                    "cumulative_risk_score": ueba.cumulative_risk_score,
                    "first_seen": ueba.created_at,
                    "last_seen": ueba.updated_at,
                }

        result["summary"] = {
            "alert_count": len(result["alerts"]),
            "incident_count": len(result["incidents"]),
            "ioc_hits": len(result["iocs"]),
            "blocked": len(result["blocked"]),
            "max_risk_score": max_risk,
            "attack_breakdown": [
                {"attack_type": k, "count": v}
                for k, v in sorted(attack_counter.items(), key=lambda x: -x[1])
            ],
        }
        return result
    finally:
        db.close()
