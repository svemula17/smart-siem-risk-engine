"""Database backup and restore utilities."""
import gzip
import logging
import shutil
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class BackupManager:
    """Manage database backups."""

    def __init__(self, backup_dir: str = "data/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, db_path: str = "smart_siem.db") -> str | None:
        """Create a compressed backup of the database.

        Returns:
            Backup file path if successful, None otherwise
        """
        try:
            db_file = Path(db_path)
            if not db_file.exists():
                logger.error(f"Database file not found: {db_path}")
                return None

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_name = f"smart_siem_{timestamp}.db.gz"
            backup_path = self.backup_dir / backup_name

            with open(db_file, "rb") as f_in:
                with gzip.open(backup_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            logger.info(f"Backup created: {backup_path}")
            return str(backup_path)
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None

    def restore_backup(self, backup_path: str, db_path: str = "smart_siem.db") -> bool:
        """Restore database from backup.

        Args:
            backup_path: Path to backup file
            db_path: Target database file path

        Returns:
            True if successful, False otherwise
        """
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False

            db_file = Path(db_path)
            # Create backup of current DB first
            if db_file.exists():
                pre_restore_backup = self.create_backup(db_path)
                logger.info(f"Pre-restore backup created: {pre_restore_backup}")

            with gzip.open(backup_file, "rb") as f_in:
                with open(db_file, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            logger.info(f"Database restored from: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def list_backups(self) -> list[dict]:
        """List all available backups.

        Returns:
            List of backup info dicts with name, size, created_at
        """
        backups = []
        try:
            for backup_file in sorted(self.backup_dir.glob("smart_siem_*.db.gz"), reverse=True):
                stat = backup_file.stat()
                backups.append({
                    "name": backup_file.name,
                    "path": str(backup_file),
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")

        return backups

    def delete_backup(self, backup_name: str) -> bool:
        """Delete a specific backup."""
        try:
            backup_path = self.backup_dir / backup_name
            if backup_path.exists() and backup_path.parent == self.backup_dir:
                backup_path.unlink()
                logger.info(f"Backup deleted: {backup_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete backup: {e}")
            return False

    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """Delete old backups, keeping only the most recent ones.

        Returns:
            Number of backups deleted
        """
        try:
            backups = sorted(self.backup_dir.glob("smart_siem_*.db.gz"), reverse=True)
            deleted = 0
            for backup_file in backups[keep_count:]:
                backup_file.unlink()
                deleted += 1
            logger.info(f"Cleaned up {deleted} old backups")
            return deleted
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0


backup_manager = BackupManager()
