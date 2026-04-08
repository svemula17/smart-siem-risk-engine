import json
import logging
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.db_models import IncidentDB, IncidentTimelineDB

logger = logging.getLogger(__name__)

def create_incident(
    db: Session, 
    title: str, 
    description: str, 
    severity: str, 
    alert_ids: List[str]
) -> IncidentDB:
    incident_id = str(uuid.uuid4())
    
    incident = IncidentDB(
        id=incident_id,
        title=title,
        description=description,
        status="Open",
        severity=severity,
        assignee_id=None,
        created_at=datetime.utcnow().isoformat(),
        updated_at=datetime.utcnow().isoformat(),
        alerts_json=json.dumps(alert_ids)
    )
    
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    add_timeline_event(db, incident_id, f"Incident created automatically from {len(alert_ids)} alerts.")
    
    return incident

def add_timeline_event(db: Session, incident_id: str, description: str) -> None:
    event = IncidentTimelineDB(
        incident_id=incident_id,
        event_description=description,
        created_at=datetime.utcnow().isoformat()
    )
    db.add(event)
    db.commit()

def update_incident_status(db: Session, incident_id: str, new_status: str, user_name: str = "System") -> Optional[IncidentDB]:
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        return None
        
    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.utcnow().isoformat()
    
    db.commit()
    db.refresh(incident)
    
    add_timeline_event(db, incident_id, f"Status changed from {old_status} to {new_status} by {user_name}.")
    
    return incident

def assign_incident(db: Session, incident_id: str, user_id: int, user_name: str) -> Optional[IncidentDB]:
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        return None
        
    incident.assignee_id = user_id
    incident.updated_at = datetime.utcnow().isoformat()
    
    db.commit()
    db.refresh(incident)
    
    add_timeline_event(db, incident_id, f"Incident assigned to {user_name}.")
    
    return incident

def get_recent_incidents(db: Session, limit: int = 50) -> List[IncidentDB]:
    return db.query(IncidentDB).order_by(IncidentDB.created_at.desc()).limit(limit).all()

def get_incident_details(db: Session, incident_id: str):
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        return None
        
    timeline = db.query(IncidentTimelineDB).filter(IncidentTimelineDB.incident_id == incident_id).order_by(IncidentTimelineDB.created_at.desc()).all()
    
    return {
        "incident": incident,
        "timeline": timeline
    }
