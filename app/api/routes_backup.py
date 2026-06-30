"""Database backup and restore endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.backup_restore import backup_manager
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api/v1/backup", tags=["Backup & Restore"])


class RestoreRequest(BaseModel):
    backup_name: str


@router.post("/create")
def create_backup(db: Session = Depends(get_db)):
    """Create a new database backup."""
    backup_path = backup_manager.create_backup()
    if backup_path:
        log_action(db, actor="admin", action="create_backup", target=backup_path)
        return {"status": "success", "backup_path": backup_path}
    else:
        log_action(db, actor="admin", action="create_backup", result="failure")
        raise HTTPException(status_code=500, detail="Backup creation failed")


@router.get("/list")
def list_backups(db: Session = Depends(get_db)):
    """List all available backups."""
    backups = backup_manager.list_backups()
    return {"backups": backups, "count": len(backups)}


@router.post("/restore")
def restore_backup(req: RestoreRequest, db: Session = Depends(get_db)):
    """Restore database from a backup."""
    backups = backup_manager.list_backups()
    backup_paths = {b["name"]: b["path"] for b in backups}

    if req.backup_name not in backup_paths:
        raise HTTPException(status_code=404, detail="Backup not found")

    success = backup_manager.restore_backup(backup_paths[req.backup_name])
    if success:
        log_action(db, actor="admin", action="restore_backup", target=req.backup_name)
        return {"status": "success", "message": "Database restored"}
    else:
        log_action(db, actor="admin", action="restore_backup", result="failure")
        raise HTTPException(status_code=500, detail="Restore failed")


@router.post("/cleanup")
def cleanup_old_backups(keep_count: int = 10, db: Session = Depends(get_db)):
    """Delete old backups, keeping only the most recent ones."""
    deleted = backup_manager.cleanup_old_backups(keep_count)
    log_action(db, actor="admin", action="cleanup_backups", target=f"kept_{keep_count}")
    return {"status": "success", "deleted_count": deleted}
