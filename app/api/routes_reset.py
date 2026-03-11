import json
from pathlib import Path

from fastapi import APIRouter

from app.database import SessionLocal
from app.models.db_models import BlockedIPDB, EvaluationResultDB, NormalizedAlertDB, ScoredAlertDB

router = APIRouter()

BLOCKLIST_FILE = Path("data/blocklist/blocked_ips.json")


@router.post("/reset")
def reset_demo_data() -> dict:
    db = SessionLocal()
    try:
        normalized_deleted = db.query(NormalizedAlertDB).delete()
        scored_deleted = db.query(ScoredAlertDB).delete()
        evaluation_deleted = db.query(EvaluationResultDB).delete()
        blocked_deleted = db.query(BlockedIPDB).delete()
        db.commit()

        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with BLOCKLIST_FILE.open("w", encoding="utf-8") as file:
            json.dump([], file, indent=2)

        return {
            "status": "success",
            "message": "Demo data reset completed",
            "deleted": {
                "normalized_alerts": normalized_deleted,
                "scored_alerts": scored_deleted,
                "evaluation_results": evaluation_deleted,
                "blocked_ips": blocked_deleted,
            },
            "raw_alerts_kept": True,
        }
    finally:
        db.close()