from datetime import datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.incident_service import (
    assign_incident,
    get_incident_details,
    get_recent_incidents,
    update_incident_status,
)

router = APIRouter(prefix="/api/v1/incidents")

# SLA thresholds (in hours) by severity — time-to-resolve
SLA_HOURS = {"Critical": 1, "High": 4, "Medium": 24, "Low": 72}


def _parse_iso(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _compute_sla(inc) -> dict:
    threshold = SLA_HOURS.get(inc.severity, 24)
    created = _parse_iso(inc.created_at)
    if not created:
        return {"sla_status": "unknown", "elapsed_hours": 0, "threshold_hours": threshold, "breach_pct": 0}
    end = _parse_iso(inc.updated_at) if inc.status == "Closed" else datetime.utcnow()
    elapsed = (end - created).total_seconds() / 3600.0
    pct = (elapsed / threshold) * 100 if threshold else 0
    if inc.status == "Closed":
        status = "met" if elapsed <= threshold else "breached"
    elif pct >= 100:
        status = "breached"
    elif pct >= 50:
        status = "warning"
    else:
        status = "ok"
    return {
        "sla_status": status,
        "elapsed_hours": round(elapsed, 2),
        "threshold_hours": threshold,
        "breach_pct": round(pct, 1),
    }


@router.get("/")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    incidents = get_recent_incidents(db, limit=limit)
    out = []
    for inc in incidents:
        d = {
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "status": inc.status,
            "severity": inc.severity,
            "assignee_id": inc.assignee_id,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at,
            "alerts_json": inc.alerts_json,
            "sla": _compute_sla(inc),
        }
        out.append(d)
    return out


class BulkRequest(BaseModel):
    incident_ids: list[str]
    user: str = "Admin"


@router.post("/bulk/close")
def bulk_close(req: BulkRequest, db: Session = Depends(get_db)):
    closed = []
    for iid in req.incident_ids:
        if update_incident_status(db, iid, "Closed", req.user):
            closed.append(iid)
    return {"closed": closed, "count": len(closed)}


@router.post("/bulk/assign")
def bulk_assign(req: BulkRequest, user_id: int, user_name: str, db: Session = Depends(get_db)):
    assigned = []
    for iid in req.incident_ids:
        if assign_incident(db, iid, user_id, user_name):
            assigned.append(iid)
    return {"assigned": assigned, "count": len(assigned)}

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    details = get_incident_details(db, incident_id)
    if not details:
        raise HTTPException(status_code=404, detail="Incident not found")
    return details

@router.put("/{incident_id}/status")
def update_status(incident_id: str, status: str, user: str = "System", db: Session = Depends(get_db)):
    updated = update_incident_status(db, incident_id, status, user)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return updated

@router.get("/{incident_id}/report")
def download_report(incident_id: str, db: Session = Depends(get_db)):
    details = get_incident_details(db, incident_id)
    if not details:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc = details["incident"]
    timeline = details["timeline"] or []
    timeline_html = "".join(
        f"<li><span class='ts'>[{escape(str(t.created_at))}]</span> {escape(t.event_description or '')}</li>"
        for t in timeline
    ) or "<li>No events.</li>"
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Incident Report — {escape(inc.id)}</title>
<style>body{{font-family:Arial,sans-serif;margin:40px;background:#f7f9fc;color:#222}}
h1,h2{{color:#1f4e79}}.card{{background:#fff;padding:20px;margin-bottom:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.label{{font-weight:bold}}.sev{{display:inline-block;padding:3px 10px;border-radius:4px;color:#fff;font-weight:bold;background:#b22222}}
ul{{padding-left:20px}}.ts{{color:#888;font-size:.85em}}.brand{{color:#888;font-size:.8em;margin-top:30px;text-align:center}}</style></head>
<body><h1>Incident Report</h1>
<div class="card"><h2>Overview</h2>
<p><span class="label">Incident ID:</span> {escape(inc.id)}</p>
<p><span class="label">Title:</span> {escape(inc.title or '')}</p>
<p><span class="label">Severity:</span> <span class="sev">{escape(inc.severity or '')}</span></p>
<p><span class="label">Status:</span> {escape(inc.status or '')}</p>
<p><span class="label">Created:</span> {escape(str(inc.created_at))}</p>
<p><span class="label">Updated:</span> {escape(str(inc.updated_at))}</p>
<p><span class="label">Description:</span><br>{escape(inc.description or 'No description.')}</p></div>
<div class="card"><h2>Activity Timeline</h2><ul>{timeline_html}</ul></div>
<div class="brand">Generated by Smart SIEM Risk Engine</div>
<div style="text-align:center;margin-top:14px"><button onclick="window.print()" style="padding:8px 16px;border:none;border-radius:6px;background:#1f4e79;color:#fff;font-weight:bold;cursor:pointer">🖨 Print / Save as PDF</button></div>
<style media="print">button{{display:none!important}}</style>
</body></html>"""
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="incident_{inc.id}.html"'},
    )


@router.put("/{incident_id}/assign")
def assign(incident_id: str, user_id: int, user_name: str, db: Session = Depends(get_db)):
    updated = assign_incident(db, incident_id, user_id, user_name)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return updated
