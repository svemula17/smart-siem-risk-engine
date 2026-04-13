from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.db_models import IPEntityProfileDB

router = APIRouter(prefix="/api/v1/ueba", tags=["UEBA"])

@router.get("/top-risky")
def get_top_risky_entities(limit: int = 5, db: Session = Depends(get_db)):
    """
    Returns the top N riskiest entities tracked by the UEBA engine.
    """
    profiles = db.query(IPEntityProfileDB).order_by(desc(IPEntityProfileDB.cumulative_risk_score)).limit(limit).all()
    return profiles
