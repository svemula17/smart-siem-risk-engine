"""Application settings, loaded from environment variables / .env file."""
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    DATABASE_URL: str = "sqlite:///smart_siem.db"
    SECRET_KEY: str = ""
    LOG_LEVEL: str = "INFO"

    # Authentication
    ADMIN_PASSWORD: str = ""
    SESSION_TTL_HOURS: int = 8
    COOKIE_SECURE: bool = False
    CORS_ORIGINS: str = ""  # comma-separated; empty = same-origin only
    INTERNAL_API_TOKEN: str = ""

    # Demo behavior
    DEMO_MODE: bool = True
    AUTO_PIPELINE: bool = True

    # Integrations
    ANTHROPIC_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    THREAT_FEED_SYNC_MINUTES: int = 60
    SLACK_WEBHOOK_URL: str = ""
    DISCORD_WEBHOOK_URL: str = ""

    # Syslog ingestion
    SYSLOG_ENABLED: bool = False
    SYSLOG_UDP_PORT: int = 5514
    SYSLOG_TCP_PORT: int = 5515

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()

# Tokens that must exist even when not configured: generate per-process values
# so the app is secure by default without a .env file.
if not settings.SECRET_KEY:
    settings.SECRET_KEY = secrets.token_urlsafe(48)
if not settings.INTERNAL_API_TOKEN:
    settings.INTERNAL_API_TOKEN = secrets.token_urlsafe(32)

# Backward-compatible module-level alias (app.database imports this).
DATABASE_URL = settings.DATABASE_URL
