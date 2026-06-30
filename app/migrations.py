"""Database migrations system."""
import logging
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

MIGRATIONS = [
    {
        "version": 1,
        "name": "initial_schema",
        "description": "Initial database schema",
        "up": None,  # Schema is created by SQLAlchemy create_all
    },
    {
        "version": 2,
        "name": "add_api_keys_table",
        "description": "Add API key management tables",
        "up": """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            key VARCHAR UNIQUE NOT NULL,
            secret_hash VARCHAR NOT NULL,
            name VARCHAR NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            last_used_at VARCHAR,
            created_at VARCHAR NOT NULL,
            expires_at VARCHAR,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
        """,
    },
    {
        "version": 3,
        "name": "add_geoip_cache_table",
        "description": "Add GeoIP caching table",
        "up": """
        CREATE TABLE IF NOT EXISTS geoip_cache (
            id INTEGER PRIMARY KEY,
            ip_address VARCHAR UNIQUE NOT NULL,
            country VARCHAR,
            city VARCHAR,
            latitude FLOAT,
            longitude FLOAT,
            isp VARCHAR,
            risk_score FLOAT DEFAULT 0.0,
            cached_at VARCHAR NOT NULL,
            expires_at VARCHAR
        );
        CREATE INDEX IF NOT EXISTS idx_geoip_ip ON geoip_cache(ip_address);
        """,
    },
    {
        "version": 4,
        "name": "add_webhook_signatures",
        "description": "Add webhook signature verification fields",
        "up": """
        ALTER TABLE playbook_executions ADD COLUMN webhook_signature VARCHAR;
        ALTER TABLE playbook_executions ADD COLUMN webhook_timestamp VARCHAR;
        """,
    },
]


class Migration:
    """Migration tracker and executor."""

    def __init__(self, db: Session):
        self.db = db

    def init_migration_table(self):
        """Create migration tracking table."""
        with self.db.begin():
            self.db.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY,
                    version INTEGER UNIQUE NOT NULL,
                    name VARCHAR NOT NULL,
                    description VARCHAR,
                    applied_at VARCHAR NOT NULL
                )
            """))

    def get_current_version(self) -> int:
        """Get current schema version."""
        result = self.db.execute(text(
            "SELECT MAX(version) FROM schema_migrations"
        )).scalar()
        return result or 0

    def apply_migration(self, migration: dict) -> bool:
        """Apply a migration."""
        try:
            version = migration["version"]
            if self.get_current_version() >= version:
                logger.info(f"Migration {version} already applied")
                return True

            if migration.get("up"):
                logger.info(f"Applying migration {version}: {migration['name']}")
                with self.db.begin():
                    self.db.execute(text(migration["up"]))

                with self.db.begin():
                    self.db.execute(text(
                        "INSERT INTO schema_migrations (version, name, description, applied_at) "
                        "VALUES (:version, :name, :description, :applied_at)"
                    ), {
                        "version": version,
                        "name": migration["name"],
                        "description": migration.get("description", ""),
                        "applied_at": datetime.utcnow().isoformat(),
                    })

            logger.info(f"Migration {version} applied successfully")
            return True
        except Exception as e:
            logger.error(f"Migration {version} failed: {e}")
            return False

    def apply_all_pending(self):
        """Apply all pending migrations."""
        self.init_migration_table()
        current = self.get_current_version()

        for migration in MIGRATIONS:
            if migration["version"] > current:
                if not self.apply_migration(migration):
                    logger.error(f"Stopping at migration {migration['version']}")
                    return False

        logger.info(f"All migrations applied. Current version: {self.get_current_version()}")
        return True
