from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import CorrelationRuleDB

router = APIRouter(prefix="/api/v1/rules")

@router.get("/")
def get_rules(db: Session = Depends(get_db)):
    return db.query(CorrelationRuleDB).all()

@router.post("/")
def create_rule(name: str, logic_json: str, severity: str, description: str = "", db: Session = Depends(get_db)):
    rule = CorrelationRuleDB(
        name=name,
        logic_json=logic_json,
        severity=severity,
        description=description,
        is_active=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule
