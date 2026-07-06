"""Persist nodes and edges to SQLite with upsert semantics."""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.db_models import GraphEdgeDB, GraphNodeDB


def _now() -> str:
    return datetime.utcnow().isoformat()


def upsert_node(
    db: Session,
    node_type: str,
    value: str,
    tier: str | None = None,
    risk_delta: int = 0,
) -> GraphNodeDB:
    if not value:
        return None
    node = (
        db.query(GraphNodeDB)
        .filter(GraphNodeDB.node_type == node_type, GraphNodeDB.value == value)
        .first()
    )
    now = _now()
    if node is None:
        node = GraphNodeDB(
            node_type=node_type,
            value=value,
            tier=tier,
            risk_score=max(0, risk_delta),
            first_seen=now,
            last_seen=now,
        )
        db.add(node)
        db.flush()
    else:
        node.last_seen = now
        if risk_delta:
            node.risk_score = min(1000, node.risk_score + risk_delta)
        if tier and not node.tier:
            node.tier = tier
    return node


def upsert_edge(
    db: Session,
    src: GraphNodeDB,
    dst: GraphNodeDB,
    relation: str,
    raw_alert_id: str | None = None,
    weight: float = 1.0,
) -> GraphEdgeDB | None:
    if src is None or dst is None or src.id == dst.id:
        return None
    edge = (
        db.query(GraphEdgeDB)
        .filter(
            GraphEdgeDB.src_node_id == src.id,
            GraphEdgeDB.dst_node_id == dst.id,
            GraphEdgeDB.relation == relation,
        )
        .first()
    )
    now = _now()
    if edge is None:
        edge = GraphEdgeDB(
            src_node_id=src.id,
            dst_node_id=dst.id,
            relation=relation,
            raw_alert_id=raw_alert_id,
            weight=weight,
            count=1,
            first_seen=now,
            last_seen=now,
        )
        db.add(edge)
        db.flush()
    else:
        edge.count += 1
        edge.last_seen = now
        edge.weight = min(100.0, edge.weight + weight * 0.1)
        if raw_alert_id:
            edge.raw_alert_id = raw_alert_id
    return edge


def classify_tier(node_type: str, value: str) -> str | None:
    """Best-effort tier classification — overridable later via UI."""
    if node_type == "ip":
        v = value or ""
        if v.startswith("10.") or v.startswith("192.168.") or v.startswith("172.16."):
            return "internal"
        if v.startswith("127."):
            return "internal"
        return "external"
    if node_type == "user":
        v = (value or "").lower()
        if any(t in v for t in ("admin", "root", "svc_", "administrator", "domain admin")):
            return "privileged"
        return "user"
    if node_type == "host":
        v = (value or "").lower()
        if any(t in v for t in ("dc-", "domain-controller", "admin-", "jump", "bastion")):
            return "privileged"
        return "internal"
    return None
