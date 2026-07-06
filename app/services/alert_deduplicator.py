"""
Alert Deduplicator — AI/ML Alert Fatigue Reduction Service

Uses two complementary techniques:
1. Fingerprint-based deduplication: alerts with same (source_ip, attack_type, event_type)
   within a configurable time window are collapsed into a single representative alert.
2. ML clustering (DBSCAN): groups alerts by feature similarity so analysts see
   cluster summaries rather than hundreds of nearly identical events.

Both techniques write suppression records to SuppressedAlertDB for fatigue metrics.
"""
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.db_models import NormalizedAlertDB, ScoredAlertDB, SuppressedAlertDB

# Deduplication window in minutes
DEDUP_WINDOW_MINUTES = 15

# In-memory fingerprint cache: fingerprint → last_seen datetime
_fingerprint_cache: dict[str, datetime] = {}


def _make_fingerprint(source_ip: str | None, attack_type: str | None, event_type: str) -> str:
    raw = f"{source_ip or 'unknown'}|{attack_type or 'unknown'}|{event_type}"
    return hashlib.md5(raw.encode()).hexdigest()


def is_duplicate(
    db: Session,
    normalized: NormalizedAlertDB,
    attack_type: str,
) -> bool:
    """
    Return True if this alert is a duplicate within the dedup window.
    Writes a SuppressedAlertDB record when suppressing.
    """
    fp = _make_fingerprint(normalized.source_ip, attack_type, normalized.event_type)
    now = datetime.utcnow()
    window = timedelta(minutes=DEDUP_WINDOW_MINUTES)

    if fp in _fingerprint_cache:
        last_seen = _fingerprint_cache[fp]
        if now - last_seen < window:
            # Suppress — record it
            record = SuppressedAlertDB(
                fingerprint=fp,
                raw_alert_id=normalized.raw_alert_id,
                attack_type=attack_type,
                source_ip=normalized.source_ip,
                suppressed_at=now.isoformat(),
                reason="duplicate_within_window",
            )
            db.add(record)
            db.commit()
            return True

    # New or expired — update cache
    _fingerprint_cache[fp] = now
    return False


def get_fatigue_metrics(db: Session) -> dict:
    """
    Compute alert fatigue reduction stats from the database.
    Returns suppression rate, top suppressed attack types, and recent counts.
    """
    from sqlalchemy import func

    total_normalized = db.query(func.count(NormalizedAlertDB.id)).scalar() or 0
    total_suppressed = db.query(func.count(SuppressedAlertDB.id)).scalar() or 0

    suppression_rate = round((total_suppressed / max(total_normalized + total_suppressed, 1)) * 100, 1)

    # Top suppressed attack types
    top_suppressed_raw = (
        db.query(SuppressedAlertDB.attack_type, func.count(SuppressedAlertDB.id).label("count"))
        .group_by(SuppressedAlertDB.attack_type)
        .order_by(func.count(SuppressedAlertDB.id).desc())
        .limit(5)
        .all()
    )
    top_suppressed = [{"attack_type": r[0] or "Unknown", "count": r[1]} for r in top_suppressed_raw]

    return {
        "total_alerts": total_normalized,
        "suppressed_alerts": total_suppressed,
        "suppression_rate_pct": suppression_rate,
        "top_suppressed": top_suppressed,
    }


def cluster_alerts_by_similarity(db: Session, limit: int = 2000) -> dict:
    """
    Use DBSCAN to cluster recent alerts by feature similarity.
    Features: [risk_score, raw_severity, mitre_count]

    Returns cluster summary: {cluster_id: {count, attack_types, avg_risk, representative_ip}}
    Falls back gracefully if sklearn unavailable or insufficient data.
    """
    import json

    try:
        import numpy as np
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return {}

    rows = (
        db.query(NormalizedAlertDB, ScoredAlertDB)
        .join(ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id)
        .order_by(ScoredAlertDB.id.desc())
        .limit(limit)
        .all()
    )

    if len(rows) < 10:
        return {}

    feature_matrix = []
    meta = []

    for norm, scored in rows:
        try:
            mitre_count = len(json.loads(norm.mitre_ids_json)) if norm.mitre_ids_json else 0
        except Exception:
            mitre_count = 0

        feature_matrix.append([scored.risk_score, norm.raw_severity, mitre_count])
        meta.append({
            "attack_type": norm.attack_type or "Unknown Threat",
            "source_ip": norm.source_ip or "N/A",
            "risk_score": scored.risk_score,
        })

    X = np.array(feature_matrix, dtype=float)
    X_scaled = StandardScaler().fit_transform(X)

    db_model = DBSCAN(eps=0.5, min_samples=5)
    labels = db_model.fit_predict(X_scaled)

    clusters: dict[int, dict] = defaultdict(lambda: {
        "count": 0, "attack_types": defaultdict(int), "risk_scores": [], "ips": set()
    })

    for label, item in zip(labels, meta, strict=False):
        clusters[int(label)]["count"] += 1
        clusters[int(label)]["attack_types"][item["attack_type"]] += 1
        clusters[int(label)]["risk_scores"].append(item["risk_score"])
        clusters[int(label)]["ips"].add(item["source_ip"])

    summary = {}
    for cid, data in clusters.items():
        top_attack = max(data["attack_types"], key=data["attack_types"].get)
        summary[cid] = {
            "cluster_id": cid,
            "alert_count": data["count"],
            "top_attack_type": top_attack,
            "avg_risk_score": round(sum(data["risk_scores"]) / len(data["risk_scores"]), 1),
            "unique_sources": len(data["ips"]),
            "label": "Noise" if cid == -1 else f"Cluster {cid}",
        }

    return summary
