from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.services.incident_service import get_recent_incidents, get_incident_details, update_incident_status, assign_incident

router = APIRouter(prefix="/api/v1/incidents")

@router.get("/")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    incidents = get_recent_incidents(db, limit=limit)
    return incidents

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

@router.put("/{incident_id}/assign")
def assign(incident_id: str, user_id: int, user_name: str, db: Session = Depends(get_db)):
    updated = assign_incident(db, incident_id, user_id, user_name)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return updated
