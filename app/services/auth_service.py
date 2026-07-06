import hashlib
import logging
import secrets

from sqlalchemy.orm import Session

from app.models.db_models import UserDB

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self):
        self.mock_users_created = False

    def hash_password(self, password: str) -> str:
        """Hash password using PBKDF2."""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${pwd_hash.hex()}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        try:
            salt, pwd_hash = password_hash.split('$')
            new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return new_hash.hex() == pwd_hash
        except Exception:
            return False

    def ensure_admin_user(self, db: Session):
        """Create the initial admin user on first boot — no default credentials.

        Uses ADMIN_PASSWORD from the environment when set; otherwise generates a
        random password and prints it to the console exactly once.
        """
        if self.mock_users_created:
            return

        if db.query(UserDB).count() == 0:
            from app.config import settings
            password = settings.ADMIN_PASSWORD or secrets.token_urlsafe(12)
            db.add(UserDB(username="admin", password_hash=self.hash_password(password), role="Admin"))
            db.commit()
            if settings.ADMIN_PASSWORD:
                logger.info("Admin user created with password from ADMIN_PASSWORD.")
            else:
                print(
                    "\n" + "=" * 62
                    + "\n  FIRST BOOT — admin account created"
                    + f"\n  username: admin\n  password: {password}"
                    + "\n  (set ADMIN_PASSWORD in .env to choose your own)"
                    + "\n" + "=" * 62 + "\n"
                )

        self.mock_users_created = True

    def get_user_by_username(self, db: Session, username: str) -> UserDB | None:
        return db.query(UserDB).filter(UserDB.username == username).first()

    def get_all_users(self, db: Session):
        return db.query(UserDB).all()

# Singleton
auth_service = AuthService()
