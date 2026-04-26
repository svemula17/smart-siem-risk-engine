"""MITRE ATT&CK heatmap aggregating technique frequency from normalized alerts."""
import json
from collections import Counter

from fastapi import APIRouter

from app.database import SessionLocal
from app.models.db_models import NormalizedAlertDB

router = APIRouter()

# Minimal MITRE technique → tactic mapping for common IDs seen in this engine.
TECHNIQUE_TACTIC = {
    "T1110": "Credential Access",
    "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1078": "Initial Access",
    "T1133": "Initial Access",
    "T1190": "Initial Access",
    "T1566": "Initial Access",
    "T1595": "Reconnaissance",
    "T1595.001": "Reconnaissance",
    "T1595.002": "Reconnaissance",
    "T1046": "Discovery",
    "T1018": "Discovery",
    "T1021": "Lateral Movement",
    "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1095": "Command and Control",
    "T1499": "Impact",
    "T1498": "Impact",
    "T1486": "Impact",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1003": "Credential Access",
    "T1083": "Discovery",
    "T1057": "Discovery",
    "T1087": "Discovery",
}

TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


@router.get("/api/v1/mitre/heatmap")
def get_mitre_heatmap(limit: int = 5000):
    """Return MITRE technique frequency grouped by tactic."""
    db = SessionLocal()
    try:
        rows = db.query(NormalizedAlertDB.mitre_ids_json).limit(limit).all()
        counter: Counter = Counter()
        for (mj,) in rows:
            try:
                ids = json.loads(mj) if mj else []
                counter.update(ids)
            except Exception:
                pass

        max_count = max(counter.values(), default=1)

        tactics: dict = {t: [] for t in TACTIC_ORDER}
        unknown: list = []
        for tid, count in counter.most_common():
            tactic = TECHNIQUE_TACTIC.get(tid)
            entry = {
                "id": tid,
                "count": count,
                "intensity": round(count / max_count, 3),
            }
            if tactic and tactic in tactics:
                tactics[tactic].append(entry)
            else:
                unknown.append(entry)

        return {
            "total_techniques": len(counter),
            "total_alerts_with_ttp": sum(counter.values()),
            "max_count": max_count,
            "tactics": [
                {"name": t, "techniques": tactics[t]} for t in TACTIC_ORDER
            ],
            "uncategorized": unknown[:30],
        }
    finally:
        db.close()
