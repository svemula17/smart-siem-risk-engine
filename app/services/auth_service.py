import logging
import secrets
import hashlib
from typing import Optional
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

    def init_mock_users(self, db: Session):
        """Creates default users for the simulation if they don't exist."""
        if self.mock_users_created:
            return

        if db.query(UserDB).count() == 0:
            users = [
                UserDB(username="admin", password_hash=self.hash_password("admin123!"), role="Admin"),
                UserDB(username="analyst_1", password_hash=self.hash_password("analyst123!"), role="Analyst"),
                UserDB(username="viewer_1", password_hash=self.hash_password("viewer123!"), role="Viewer")
            ]
            db.add_all(users)
            db.commit()
            logger.info("Mock users initialized with strong passwords.")

        self.mock_users_created = True

    def get_user_by_username(self, db: Session, username: str) -> Optional[UserDB]:
        return db.query(UserDB).filter(UserDB.username == username).first()

    def get_all_users(self, db: Session):
        return db.query(UserDB).all()

# Singleton
auth_service = AuthService()
