"""
Generic Webhook Receiver
Accepts alerts from external tools (Splunk, PagerDuty, custom scripts)
and normalizes them into the SIEM pipeline.
"""
import json
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request

from app.database import SessionLocal
from app.models.db_models import AuditLogDB

router = APIRouter()

# In-memory buffer of received webhooks (last 100)
_webhook_buffer: list = []


@router.post("/api/webhook/ingest")
async def receive_webhook(request: Request):
    """Accept any JSON payload and store it as a raw webhook event."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from None

    event = {
        "received_at": datetime.utcnow().isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "payload": body,
    }
    _webhook_buffer.append(event)
    if len(_webhook_buffer) > 100:
        _webhook_buffer.pop(0)

    # Log the ingestion
    db = SessionLocal()
    try:
        db.add(AuditLogDB(
            actor="webhook",
            action="ingest_webhook",
            target=request.client.host if request.client else "unknown",
            detail=json.dumps(body)[:500],
            result="success",
            created_at=datetime.utcnow().isoformat(),
        ))
        db.commit()
    finally:
        db.close()

    return {"status": "received", "timestamp": event["received_at"]}


@router.get("/api/webhook/events")
def get_webhook_events():
    """Return recent webhook events received."""
    return {"events": list(reversed(_webhook_buffer[-50:]))}


@router.post("/api/webhook/test")
async def test_webhook(request: Request):
    """Echo back the received payload — useful for testing integrations."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {"status": "echo", "received": body, "timestamp": datetime.utcnow().isoformat()}
