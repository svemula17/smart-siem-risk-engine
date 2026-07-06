import os
import sys

# Add parent directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, SessionLocal, engine
from app.models.db_models import CorrelationRuleDB
from app.services.auth_service import auth_service


def seed_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Seed the initial admin (ADMIN_PASSWORD env or random, printed once)
        auth_service.ensure_admin_user(db)

        # Seed Correlation Rules
        if db.query(CorrelationRuleDB).count() == 0:
            rule1 = CorrelationRuleDB(
                name="Potential Ransomware / T1486",
                description="High risk alert mapped to Data Encrypted for Impact.",
                logic_json='{"type": "mitre_tactic", "mitre_id": "T1486", "min_risk": 90}',
                severity="Critical"
            )
            rule2 = CorrelationRuleDB(
                name="Brute Force Detected / T1110",
                description="Multiple failed logins followed by potential success or just high risk brute force.",
                logic_json='{"type": "mitre_tactic", "mitre_id": "T1110", "min_risk": 80}',
                severity="High"
            )
            rule3 = CorrelationRuleDB(
                name="Suspicious Network Traffic / T1071",
                description="Application Layer Protocol used for C2",
                logic_json='{"type": "mitre_tactic", "mitre_id": "T1071", "min_risk": 75}',
                severity="Medium"
            )
            db.add_all([rule1, rule2, rule3])
            db.commit()
            print("Rules seeded.")

    finally:
        db.close()

if __name__ == "__main__":
    seed_db()
