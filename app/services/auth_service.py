import logging
from typing import Optional
from sqlalchemy.orm import Session
from app.models.db_models import UserDB

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self):
        self.mock_users_created = False

    def init_mock_users(self, db: Session):
        """Creates default users for the simulation if they don't exist."""
        if self.mock_users_created:
            return

        if db.query(UserDB).count() == 0:
            users = [
                UserDB(username="admin", password_hash="hash_admin", role="Admin"),
                UserDB(username="analyst_1", password_hash="hash_analyst", role="Analyst"),
                UserDB(username="viewer_1", password_hash="hash_viewer", role="Viewer")
            ]
            db.add_all(users)
            db.commit()
            logger.info("Mock users initialized.")
        
        self.mock_users_created = True

    def get_user_by_username(self, db: Session, username: str) -> Optional[UserDB]:
        return db.query(UserDB).filter(UserDB.username == username).first()

    def get_all_users(self, db: Session):
        return db.query(UserDB).all()

# Singleton
auth_service = AuthService()
