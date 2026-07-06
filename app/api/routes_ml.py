"""
ML Insights Routes — Model stats, retraining, auto-triage.
"""
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
from fastapi import APIRouter
from sqlalchemy import func

from app.database import SessionLocal
from app.models.db_models import (
    FalsePositiveDB,
    NormalizedAlertDB,
    ScoredAlertDB,
)
from app.services.audit_logger import log_action

router = APIRouter()
logger = logging.getLogger(__name__)

ML_META_PATH = Path("data/ml_meta.json")

_DEFAULT_FEATURES = [
    {"name": "Raw Severity", "weight": 0.55},
    {"name": "Base Risk Score", "weight": 0.33},
    {"name": "MITRE Technique Count", "weight": 0.12},
]


def _read_meta() -> dict:
    if ML_META_PATH.exists():
        try:
            return json.loads(ML_META_PATH.read_text())
        except Exception:
            pass
    return {}


def _write_meta(data: dict):
    ML_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    ML_META_PATH.write_text(json.dumps(data, default=str))


@router.get("/api/ml/stats")
def get_ml_stats():
    """Return Isolation Forest model metrics, anomaly rates, FP rate, training metadata."""
    db = SessionLocal()
    try:
        meta = _read_meta()

        # Total alerts + anomaly rate
        total_alerts = db.query(func.count(ScoredAlertDB.id)).scalar() or 1
        total_anomalies = db.query(func.count(ScoredAlertDB.id)).filter(
            ScoredAlertDB.is_anomaly == True
        ).scalar() or 0
        anomaly_rate = round(total_anomalies / total_alerts * 100, 2)

        # FP rate
        total_fp = db.query(func.count(FalsePositiveDB.id)).scalar() or 0
        fp_rate = round(total_fp / total_alerts * 100, 2)

        # Hourly anomaly counts (last 24h)
        cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        recent = db.query(ScoredAlertDB.processed_at, ScoredAlertDB.is_anomaly).filter(
            ScoredAlertDB.processed_at >= cutoff_24h
        ).all()

        hourly_counts = [0] * 24
        for ts, is_anom in recent:
            if is_anom:
                try:
                    hour = int(str(ts)[11:13])
                    hourly_counts[hour] += 1
                except Exception:
                    pass

        # Daily anomaly rates (last 7 days)
        cutoff_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
        daily_rows = db.query(ScoredAlertDB.processed_at, ScoredAlertDB.is_anomaly).filter(
            ScoredAlertDB.processed_at >= cutoff_7d
        ).all()

        daily_total: dict = defaultdict(int)
        daily_anom: dict = defaultdict(int)
        for ts, is_anom in daily_rows:
            day = str(ts)[:10]
            daily_total[day] += 1
            if is_anom:
                daily_anom[day] += 1

        # FP per day (last 7d)
        fp_rows = db.query(FalsePositiveDB.marked_at).filter(
            FalsePositiveDB.marked_at >= cutoff_7d
        ).all()
        daily_fp: dict = defaultdict(int)
        for (ts,) in fp_rows:
            daily_fp[str(ts)[:10]] += 1

        sorted_days = sorted(daily_total.keys())[-7:]
        daily_anomaly_rates = [
            {
                "day": d,
                "rate": round(daily_anom[d] / max(daily_total[d], 1) * 100, 2),
                "fp_rate": round(daily_fp[d] / max(daily_total[d], 1) * 100, 2),
                "anomaly_count": daily_anom[d],
                "total": daily_total[d],
            }
            for d in sorted_days
        ]

        from app.services.ml_engine import ml_engine
        is_trained = meta.get("is_trained", ml_engine.is_trained)
        training_samples = meta.get("training_samples", 0)
        last_trained_at = meta.get("last_trained_at")
        feature_importance = meta.get("feature_importance", _DEFAULT_FEATURES)

        return {
            "is_trained": is_trained,
            "training_samples": training_samples,
            "last_trained_at": last_trained_at,
            "anomaly_rate_pct": anomaly_rate,
            "fp_rate_pct": fp_rate,
            "total_anomalies": total_anomalies,
            "total_alerts": total_alerts,
            "total_false_positives": total_fp,
            "hourly_anomaly_counts": hourly_counts,
            "daily_anomaly_rates": daily_anomaly_rates,
            "feature_importance": feature_importance,
            "contamination": meta.get("contamination", 0.01),
        }
    finally:
        db.close()


@router.post("/api/ml/retrain")
def retrain_model():
    """Retrain Isolation Forest excluding confirmed false positives. Adjusts contamination."""
    db = SessionLocal()
    try:
        import joblib
        from sklearn.ensemble import IsolationForest

        from app.services.ml_engine import ml_engine

        # 1. Get all false positive alert IDs
        fp_ids = {fp.raw_alert_id for fp in db.query(FalsePositiveDB).all()}

        # 2. Query training data joining normalized + scored
        query_result = db.query(NormalizedAlertDB, ScoredAlertDB).join(
            ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id
        ).limit(5000).all()

        if len(query_result) < 30:
            return {"status": "error", "message": "Not enough historical data to retrain (need ≥ 30 alerts)."}

        # 3. Filter out confirmed FPs
        filtered = [(n, s) for n, s in query_result if s.raw_alert_id not in fp_ids]
        if len(filtered) < 20:
            return {"status": "error", "message": "Too many FPs filtered — too little training data remains."}

        # 4. Adjust contamination based on FP rate
        fp_rate = len(fp_ids) / max(len(query_result), 1)
        new_contamination = max(0.001, min(0.05, fp_rate * 0.5 + 0.005))

        # 5. Re-fit model
        X = [ml_engine._extract_features(n, s) for n, s in filtered]
        X_np = np.array(X)
        ml_engine.model = IsolationForest(
            n_estimators=100, contamination=new_contamination, random_state=42
        )
        ml_engine.model.fit(X_np)
        ml_engine.is_trained = True

        # 6. Persist model
        ml_engine.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(ml_engine.model, ml_engine.model_path)

        # 7. Write metadata
        meta = {
            "is_trained": True,
            "training_samples": len(X),
            "contamination": new_contamination,
            "fp_count_used": len(fp_ids),
            "last_trained_at": datetime.utcnow().isoformat(),
            "feature_importance": _DEFAULT_FEATURES,
        }
        _write_meta(meta)

        log_action(db, actor="system", action="ml_retrain",
                   target="isolation_forest",
                   detail=f"Trained on {len(X)} samples, excluded {len(fp_ids)} FPs, contamination={new_contamination:.4f}")
        db.commit()

        return {
            "status": "success",
            "message": f"Retrained on {len(X)} samples (excluded {len(fp_ids)} FPs). Contamination: {new_contamination:.4f}",
            "training_samples": len(X),
            "fp_excluded": len(fp_ids),
            "new_contamination": new_contamination,
        }
    except Exception as e:
        logger.exception("Retrain failed")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
