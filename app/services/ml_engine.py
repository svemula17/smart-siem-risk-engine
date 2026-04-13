import logging
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session
from pathlib import Path
import joblib

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
        # We need purely numeric features for IsolationForest
        # 1. raw_severity
        # 2. Number of MITRE IDs
        # 3. Base risk_score
        
        severity = norm_alert.raw_severity
        mitre_count = 0
        if isinstance(norm_alert, NormalizedAlert):
            mitre_count = len(norm_alert.mitre_ids) if norm_alert.mitre_ids else 0
        else: # SQLAlchemy model handling
            try:
                mitres = json.loads(norm_alert.mitre_ids_json)
                mitre_count = len(mitres) if mitres else 0
            except:
                pass
                
        base_risk = 50 # Default if not passed
        if scored_alert:
            base_risk = scored_alert.risk_score
            
        # Feature vector
        return [severity, mitre_count, base_risk]

    def train_on_history(self, db: Session):
        logger.info("Initiating ML Engine training phase...")
        
        # Get historical data joining normalized and scored
        query = db.query(NormalizedAlertDB, ScoredAlertDB).join(
            ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id
        ).limit(5000).all()
        
        if len(query) < 50:
            logger.warning("Not enough historical data to train the ML model securely. Waiting for stream.")
            return
            
        X = []
        for norm, scored in query:
            features = self._extract_features(norm, scored)
            X.append(features)
            
        X_train = np.array(X)
        self.model.fit(X_train)
        self.is_trained = True
        
        logger.info(f"ML Isolation Forest successfully trained on {len(X_train)} historical events.")
        
        # Cache model for next startup
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def predict_anomaly(self, normalized_alert: NormalizedAlert, scored_alert: ScoredAlert) -> bool:
        if not self.is_trained:
            return False
            
        features = self._extract_features(normalized_alert, scored_alert)
        X_test = np.array([features])
        
        # predict() returns 1 for inliers, -1 for anomalies
        prediction = self.model.predict(X_test)[0]
        
        is_anomaly = (prediction == -1)
        return is_anomaly

ml_engine = MLEngine()
