import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.models.db_models import NormalizedAlertDB, ScoredAlertDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert

logger = logging.getLogger(__name__)

class MLEngine:
    def __init__(self, model_path="data/iforest_model.pkl"):
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self.is_trained = False
        self.model_path = Path(model_path)

        # Load cached model if it exists to avoid re-training on startup
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                logger.info("Loaded pre-trained ML Isolation Forest model.")
            except Exception as e:
                logger.warning(f"Failed to load cached ML model: {e}")

    def _extract_features(self, norm_alert, scored_alert=None):
        """Extract numeric feature vector for IsolationForest."""
        severity = norm_alert.raw_severity
        mitre_count = 0
        if isinstance(norm_alert, NormalizedAlert):
            mitre_count = len(norm_alert.mitre_ids) if norm_alert.mitre_ids else 0
        else:
            try:
                mitres = json.loads(norm_alert.mitre_ids_json)
                mitre_count = len(mitres) if mitres else 0
            except Exception:
                pass

        base_risk = 50
        if scored_alert:
            base_risk = scored_alert.risk_score

        return [severity, mitre_count, base_risk]

    def train_on_history(self, db: Session):
        logger.info("Initiating ML Engine training phase...")

        query = db.query(NormalizedAlertDB, ScoredAlertDB).join(
            ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id
        ).limit(5000).all()

        if len(query) < 50:
            logger.warning("Not enough historical data to train the ML model. Waiting for more alerts.")
            return

        X = [self._extract_features(norm, scored) for norm, scored in query]
        X_train = np.array(X)
        self.model.fit(X_train)
        self.is_trained = True

        logger.info(f"ML Isolation Forest trained on {len(X_train)} historical events.")

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def predict_anomaly(self, normalized_alert: NormalizedAlert, scored_alert: ScoredAlert) -> bool:
        """Return True if the alert is anomalous. Also persists is_anomaly to DB."""
        if not self.is_trained:
            return False

        features = self._extract_features(normalized_alert, scored_alert)
        X_test = np.array([features])

        # predict() returns 1 for inliers, -1 for anomalies
        prediction = self.model.predict(X_test)[0]
        is_anomaly = (prediction == -1)
        return is_anomaly

    def predict_anomaly_with_score(self, normalized_alert: NormalizedAlert, scored_alert: ScoredAlert):
        """Return (is_anomaly: bool, anomaly_score: float 0-1)."""
        if not self.is_trained:
            return False, 0.0
        features = self._extract_features(normalized_alert, scored_alert)
        X_test = np.array([features])
        prediction = self.model.predict(X_test)[0]
        # decision_function returns negative for anomalies; normalize to 0-1
        raw_score = self.model.decision_function(X_test)[0]
        normalized_score = max(0.0, min(1.0, 1.0 / (1.0 + np.exp(raw_score * 3))))
        return prediction == -1, round(float(normalized_score), 3)

    def get_anomaly_rate(self, db: Session) -> float:
        """Compute anomaly rate from DB."""
        from sqlalchemy import func
        total = db.query(func.count(ScoredAlertDB.id)).scalar() or 1
        anomalies = db.query(func.count(ScoredAlertDB.id)).filter(
            ScoredAlertDB.is_anomaly == True
        ).scalar() or 0
        return round(anomalies / total * 100, 2)


ml_engine = MLEngine()
