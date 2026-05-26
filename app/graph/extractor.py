"""Extract graph nodes + edges from a normalized + scored alert."""
import json
import logging
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.graph.store import upsert_node, upsert_edge, classify_tier

logger = logging.getLogger(__name__)


_RELATION_BY_ATTACK = {
    "Brute Force": "authenticated_to",
    "Credential Access": "authenticated_to",
    "Lateral Movement": "authenticated_to",
    "Initial Access": "authenticated_to",
    "Command & Control": "connected_to",
    "Command and Control": "connected_to",
    "Data Exfiltration": "connected_to",
    "Exfiltration": "connected_to",
    "Reconnaissance": "connected_to",
    "Execution": "executed",
    "Persistence": "executed",
    "Privilege Escalation": "executed",
    "Defense Evasion": "executed",
}


def _payload(normalized) -> Dict[str, Any]:
    raw = getattr(normalized, "normalized_payload_json", None)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return {}


def _attr(obj, key, default=None):
    if hasattr(obj, key):
        return getattr(obj, key) or default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def extract_from_alert(db: Session, normalized, scored) -> Dict[str, Any]:
    """Hook called from the alert pipeline. Builds graph entries silently.

    `normalized` is the NormalizedAlert pydantic model from the pipeline
    (NOT the DB row), `scored` is the ScoredAlert pydantic model.
    """
    payload = _payload(normalized) if not isinstance(normalized, dict) else {}

    src_ip = _attr(normalized, "source_ip") or payload.get("source_ip")
    dst_ip = _attr(normalized, "target_ip") or payload.get("target_ip") or payload.get("destination_ip")
    user = _attr(normalized, "username") or payload.get("username") or payload.get("user")
    host = _attr(normalized, "host") or payload.get("host") or payload.get("hostname")
    process = payload.get("process") or payload.get("process_name")
    domain = payload.get("domain") or payload.get("dns_query")
    file_hash = payload.get("hash") or payload.get("file_hash") or payload.get("sha256")
    attack_type = _attr(normalized, "attack_type", "Unknown")
    raw_alert_id = _attr(normalized, "alert_id") or _attr(normalized, "raw_alert_id")
    risk = int(_attr(scored, "risk_score", 0) or 0)
    risk_delta = max(1, risk // 20)

    nodes: Dict[str, Any] = {}
    if src_ip:
        nodes["src_ip"] = upsert_node(db, "ip", src_ip, tier=classify_tier("ip", src_ip), risk_delta=risk_delta)
    if dst_ip:
        nodes["dst_ip"] = upsert_node(db, "ip", dst_ip, tier=classify_tier("ip", dst_ip), risk_delta=1)
    if user:
        nodes["user"] = upsert_node(db, "user", str(user), tier=classify_tier("user", str(user)), risk_delta=risk_delta)
    if host:
        nodes["host"] = upsert_node(db, "host", str(host), tier=classify_tier("host", str(host)), risk_delta=1)
    if process:
        nodes["process"] = upsert_node(db, "process", str(process), risk_delta=1)
    if domain:
        nodes["domain"] = upsert_node(db, "domain", str(domain), risk_delta=1)
    if file_hash:
        nodes["hash"] = upsert_node(db, "hash", str(file_hash), risk_delta=2)

    relation = _RELATION_BY_ATTACK.get(attack_type, "connected_to")

    edges = []
    # primary connection: src_ip → dst_ip or src_ip → host
    if "src_ip" in nodes and "dst_ip" in nodes:
        edges.append(upsert_edge(db, nodes["src_ip"], nodes["dst_ip"], relation, raw_alert_id, weight=1.0 + risk / 100))
    if "src_ip" in nodes and "host" in nodes:
        edges.append(upsert_edge(db, nodes["src_ip"], nodes["host"], relation, raw_alert_id, weight=1.0 + risk / 100))
    if "user" in nodes and "host" in nodes:
        edges.append(upsert_edge(db, nodes["user"], nodes["host"], "authenticated_to", raw_alert_id, weight=1.0))
    if "user" in nodes and "src_ip" in nodes:
        edges.append(upsert_edge(db, nodes["user"], nodes["src_ip"], "authenticated_to", raw_alert_id, weight=0.5))
    if "host" in nodes and "process" in nodes:
        edges.append(upsert_edge(db, nodes["host"], nodes["process"], "executed", raw_alert_id))
    if "src_ip" in nodes and "domain" in nodes:
        edges.append(upsert_edge(db, nodes["src_ip"], nodes["domain"], "resolved_to", raw_alert_id))
    if "process" in nodes and "hash" in nodes:
        edges.append(upsert_edge(db, nodes["process"], nodes["hash"], "accessed", raw_alert_id))

    try:
        db.commit()
    except Exception as e:
        logger.warning(f"[graph] commit failed: {e}")
        db.rollback()
        return {"nodes": 0, "edges": 0}

    # update in-memory graph
    try:
        from app.graph.loader import graph_loader
        graph_loader.apply_delta(nodes, [e for e in edges if e is not None], relation)
    except Exception as e:
        logger.debug(f"[graph] loader delta skipped: {e}")

    return {"nodes": len(nodes), "edges": sum(1 for e in edges if e is not None)}
