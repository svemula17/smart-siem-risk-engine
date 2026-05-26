"""Seed graph-aware correlation rules so they appear in the Rules tab.

The actual detection logic lives in path_detector.py — these rows are the
analyst-visible representation that can be toggled on/off.
"""
import json
import logging

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.db_models import CorrelationRuleDB

logger = logging.getLogger(__name__)

GRAPH_RULES = [
    {
        "name": "Graph: Fan-out Authentication",
        "description": "A single user or IP authenticates to N+ distinct hosts within a short window. Classic lateral-movement signal.",
        "severity": "High",
        "logic": {"kind": "graph", "pattern": "fan_out_auth", "threshold_hosts": 4, "window_minutes": 30},
    },
    {
        "name": "Graph: Privilege Escalation Chain",
        "description": "Path of <=3 hops from a non-privileged entity to a privileged host or account.",
        "severity": "Critical",
        "logic": {"kind": "graph", "pattern": "privilege_chain", "max_hops": 3},
    },
    {
        "name": "Graph: C2 Beacon Pattern",
        "description": "Repeated outbound connections from an internal IP to the same external destination — possible C2 beacon.",
        "severity": "High",
        "logic": {"kind": "graph", "pattern": "beacon", "min_hits": 8},
    },
    {
        "name": "Graph: Tier Boundary Crossed",
        "description": "Edge that crosses external → internal/privileged or user → privileged.",
        "severity": "High",
        "logic": {"kind": "graph", "pattern": "tier_cross"},
    },
]


def seed(db: Session = None) -> int:
    owns = db is None
    if owns:
        db = SessionLocal()
    added = 0
    try:
        for spec in GRAPH_RULES:
            existing = db.query(CorrelationRuleDB).filter(CorrelationRuleDB.name == spec["name"]).first()
            if existing:
                continue
            rule = CorrelationRuleDB(
                name=spec["name"],
                description=spec["description"],
                logic_json=json.dumps(spec["logic"]),
                severity=spec["severity"],
                is_active=True,
            )
            db.add(rule)
            added += 1
        if added:
            db.commit()
            logger.info(f"[graph] seeded {added} graph correlation rules")
        return added
    except Exception as e:
        logger.warning(f"[graph] seed failed: {e}")
        db.rollback()
        return 0
    finally:
        if owns:
            db.close()


def is_pattern_active(db: Session, pattern: str) -> bool:
    """Look up the toggle state of a graph rule by pattern name."""
    rules = db.query(CorrelationRuleDB).all()
    for r in rules:
        try:
            logic = json.loads(r.logic_json or "{}")
        except Exception:
            continue
        if logic.get("kind") == "graph" and logic.get("pattern") == pattern:
            return bool(r.is_active)
    return True  # default on if rule row missing
