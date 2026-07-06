from datetime import datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedUser, get_current_user
from app.database import get_db
from app.models.db_models import IncidentCommentDB, IncidentDB, IncidentEvidenceDB
from app.services.audit_logger import log_action
from app.services.incident_service import (
    add_timeline_event,
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
def bulk_close(req: BulkRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    closed = []
    for iid in req.incident_ids:
        if update_incident_status(db, iid, "Closed", user.username):
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
def update_status(incident_id: str, status: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    updated = update_incident_status(db, incident_id, status, user.username)
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


# ── Case management: comments, evidence, authenticated actions ─────────────────

class CommentCreate(BaseModel):
    body: str


class EvidenceCreate(BaseModel):
    evidence_type: str = "note"   # alert | ioc | note
    ref_id: str | None = None
    description: str = ""


def _require_incident(db: Session, incident_id: str) -> IncidentDB:
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/comments")
def list_comments(incident_id: str, db: Session = Depends(get_db)):
    _require_incident(db, incident_id)
    rows = (
        db.query(IncidentCommentDB)
        .filter(IncidentCommentDB.incident_id == incident_id)
        .order_by(IncidentCommentDB.id)
        .all()
    )
    return {"comments": [
        {"id": c.id, "author": c.author, "body": c.body, "created_at": c.created_at}
        for c in rows
    ]}


@router.post("/{incident_id}/comments")
def add_comment(
    incident_id: str,
    req: CommentCreate,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(get_current_user),
):
    if not req.body.strip():
        raise HTTPException(status_code=422, detail="Comment body is empty")
    _require_incident(db, incident_id)
    comment = IncidentCommentDB(
        incident_id=incident_id,
        author=user.username,
        body=req.body.strip(),
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(comment)
    db.commit()
    add_timeline_event(db, incident_id, "Comment added.", actor=user.username)
    return {"status": "created", "id": comment.id}


@router.get("/{incident_id}/evidence")
def list_evidence(incident_id: str, db: Session = Depends(get_db)):
    _require_incident(db, incident_id)
    rows = (
        db.query(IncidentEvidenceDB)
        .filter(IncidentEvidenceDB.incident_id == incident_id)
        .order_by(IncidentEvidenceDB.id)
        .all()
    )
    return {"evidence": [
        {"id": e.id, "evidence_type": e.evidence_type, "ref_id": e.ref_id,
         "description": e.description, "added_by": e.added_by, "created_at": e.created_at}
        for e in rows
    ]}


@router.post("/{incident_id}/evidence")
def add_evidence(
    incident_id: str,
    req: EvidenceCreate,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(get_current_user),
):
    if req.evidence_type not in ("alert", "ioc", "note"):
        raise HTTPException(status_code=422, detail="evidence_type must be alert, ioc, or note")
    _require_incident(db, incident_id)
    evidence = IncidentEvidenceDB(
        incident_id=incident_id,
        evidence_type=req.evidence_type,
        ref_id=req.ref_id,
        description=req.description,
        added_by=user.username,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(evidence)
    db.commit()
    add_timeline_event(
        db, incident_id,
        f"Evidence attached ({req.evidence_type}{': ' + req.ref_id if req.ref_id else ''}).",
        actor=user.username,
    )
    log_action(db, actor=user.username, action="add_evidence", target=incident_id,
               detail=f"{req.evidence_type}:{req.ref_id or '-'}")
    return {"status": "created", "id": evidence.id}


@router.delete("/{incident_id}/evidence/{evidence_id}")
def remove_evidence(
    incident_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(get_current_user),
):
    row = (
        db.query(IncidentEvidenceDB)
        .filter(IncidentEvidenceDB.id == evidence_id, IncidentEvidenceDB.incident_id == incident_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.delete(row)
    db.commit()
    add_timeline_event(db, incident_id, "Evidence removed.", actor=user.username)
    return {"status": "deleted"}


@router.get("/{incident_id}/case")
def case_detail(incident_id: str, db: Session = Depends(get_db)):
    """Full case view: incident, SLA, timeline (with actors), comments, evidence."""
    incident = _require_incident(db, incident_id)
    details = get_incident_details(db, incident_id)
    comments = list_comments(incident_id, db)["comments"]
    evidence = list_evidence(incident_id, db)["evidence"]
    return {
        "incident": {
            "id": incident.id, "title": incident.title, "description": incident.description,
            "status": incident.status, "severity": incident.severity,
            "assignee_id": incident.assignee_id, "created_at": incident.created_at,
            "updated_at": incident.updated_at, "alerts_json": incident.alerts_json,
        },
        "sla": _compute_sla(incident),
        "timeline": [
            {"description": t.event_description, "actor": getattr(t, "actor", "system"),
             "created_at": t.created_at}
            for t in details["timeline"]
        ],
        "comments": comments,
        "evidence": evidence,
    }
