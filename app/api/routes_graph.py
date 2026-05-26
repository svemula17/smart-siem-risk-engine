"""Attack graph API — neighborhood, path, lateral-movement chains, investigate."""
import json
from typing import Optional

from fastapi import APIRouter, HTTPException
from sqlalchemy import desc

from app.database import SessionLocal
from app.graph.loader import graph_loader
from app.graph.path_detector import detect_patterns
from app.models.db_models import (
    GraphEdgeDB,
    GraphNodeDB,
    LateralMovementIncidentDB,
)

router = APIRouter()


def _ensure_warm(force: bool = False):
    """Warm or re-warm the in-memory graph from DB.

    Pipeline runs in a subprocess so server's in-memory copy can lag the DB.
    On every read we cheaply check if the live edge count diverged from DB
    and re-warm when it has.
    """
    if not graph_loader.available:
        return
    if force or not graph_loader.ready:
        try:
            graph_loader.warm()
        except Exception:
            pass
        return
    # Cheap freshness check
    try:
        db = SessionLocal()
        db_edges = db.query(GraphEdgeDB).count()
        db.close()
        live = graph_loader.stats().get("edges", 0)
        if db_edges != live:
            graph_loader.warm()
    except Exception:
        pass


@router.get("/api/v1/graph/stats")
def stats():
    _ensure_warm()
    return graph_loader.stats()


@router.post("/api/v1/graph/reload")
def reload():
    _ensure_warm(force=True)
    return graph_loader.stats()


@router.get("/api/v1/graph/node/{node_type}/{value}")
def node_detail(node_type: str, value: str):
    _ensure_warm()
    db = SessionLocal()
    try:
        n = (
            db.query(GraphNodeDB)
            .filter(GraphNodeDB.node_type == node_type, GraphNodeDB.value == value)
            .first()
        )
        if not n:
            raise HTTPException(404, "node not found")
        out_edges = (
            db.query(GraphEdgeDB)
            .filter(GraphEdgeDB.src_node_id == n.id)
            .order_by(desc(GraphEdgeDB.last_seen))
            .limit(50)
            .all()
        )
        in_edges = (
            db.query(GraphEdgeDB)
            .filter(GraphEdgeDB.dst_node_id == n.id)
            .order_by(desc(GraphEdgeDB.last_seen))
            .limit(50)
            .all()
        )
        node_ids = {e.dst_node_id for e in out_edges} | {e.src_node_id for e in in_edges}
        node_map = {
            nn.id: nn for nn in db.query(GraphNodeDB).filter(GraphNodeDB.id.in_(node_ids)).all()
        }
        def fmt(e, direction):
            other_id = e.dst_node_id if direction == "out" else e.src_node_id
            other = node_map.get(other_id)
            return {
                "direction": direction,
                "relation": e.relation,
                "count": e.count,
                "weight": round(e.weight, 2),
                "last_seen": e.last_seen,
                "raw_alert_id": e.raw_alert_id,
                "other": {
                    "type": other.node_type if other else None,
                    "value": other.value if other else None,
                    "tier": other.tier if other else None,
                    "risk_score": other.risk_score if other else 0,
                },
            }
        return {
            "node": {
                "id": n.id,
                "type": n.node_type,
                "value": n.value,
                "tier": n.tier,
                "risk_score": n.risk_score,
                "first_seen": n.first_seen,
                "last_seen": n.last_seen,
            },
            "edges": [fmt(e, "out") for e in out_edges] + [fmt(e, "in") for e in in_edges],
        }
    finally:
        db.close()


@router.get("/api/v1/graph/neighborhood/{node_type}/{value}")
def neighborhood(node_type: str, value: str, depth: int = 2, cap: int = 200):
    _ensure_warm()
    if depth < 1 or depth > 4:
        raise HTTPException(400, "depth must be 1..4")
    return graph_loader.neighborhood(node_type, value, depth=depth, cap=cap)


@router.get("/api/v1/graph/all")
def all_graph(limit: int = 300):
    _ensure_warm()
    return graph_loader.serialize_full(limit=limit)


@router.get("/api/v1/graph/path")
def path(src_type: str, src_value: str, dst_type: str, dst_value: str,
         max_depth: int = 4, max_paths: int = 5):
    _ensure_warm()
    src_key = f"{src_type}:{src_value}"
    dst_key = f"{dst_type}:{dst_value}"
    paths = graph_loader.shortest_paths(src_key, dst_key, max_depth=max_depth, max_paths=max_paths)
    return {"src": src_key, "dst": dst_key, "paths": paths, "count": len(paths)}


@router.get("/api/v1/graph/lateral-chains")
def lateral_chains(limit: int = 50, status: Optional[str] = None):
    db = SessionLocal()
    try:
        q = db.query(LateralMovementIncidentDB)
        if status:
            q = q.filter(LateralMovementIncidentDB.status == status)
        rows = q.order_by(desc(LateralMovementIncidentDB.id)).limit(limit).all()
        return [
            {
                "id": r.id,
                "pattern": r.pattern,
                "severity": r.severity,
                "path": json.loads(r.path_json),
                "node_count": r.node_count,
                "alert_ids": json.loads(r.alert_ids_json),
                "description": r.description,
                "status": r.status,
                "created_at": r.created_at,
            }
            for r in rows
        ]
    finally:
        db.close()


@router.post("/api/v1/graph/lateral-chains/{chain_id}/close")
def close_chain(chain_id: int):
    db = SessionLocal()
    try:
        row = db.query(LateralMovementIncidentDB).filter(LateralMovementIncidentDB.id == chain_id).first()
        if not row:
            raise HTTPException(404, "chain not found")
        row.status = "closed"
        db.commit()
        return {"ok": True, "id": chain_id, "status": row.status}
    finally:
        db.close()


@router.post("/api/v1/graph/investigate")
def investigate(payload: dict):
    """Body: {node_type, value, depth}. Returns subgraph + narrative."""
    _ensure_warm()
    ntype = payload.get("node_type")
    value = payload.get("value")
    depth = int(payload.get("depth", 2))
    if not ntype or not value:
        raise HTTPException(400, "node_type and value required")

    sub = graph_loader.neighborhood(ntype, value, depth=depth)
    focus_key = f"{ntype}:{value}"

    # Run detectors centered on this node
    db = SessionLocal()
    try:
        patterns = detect_patterns(db, [focus_key])
    finally:
        db.close()

    narrative = _build_narrative(focus_key, sub, patterns)
    return {
        "focus": focus_key,
        "subgraph": sub,
        "patterns": patterns,
        "narrative": narrative,
    }


@router.post("/api/v1/graph/scan")
def scan(limit: int = 100):
    """Run lateral-movement detectors over the most recently active nodes."""
    _ensure_warm()
    db = SessionLocal()
    try:
        rows = (
            db.query(GraphNodeDB)
            .order_by(desc(GraphNodeDB.last_seen))
            .limit(limit)
            .all()
        )
        keys = [f"{r.node_type}:{r.value}" for r in rows]
        incs = detect_patterns(db, keys)
        return {"scanned_nodes": len(keys), "incidents": incs}
    finally:
        db.close()


def _build_narrative(focus: str, sub: dict, patterns: list) -> str:
    n_nodes = len(sub.get("nodes", []))
    n_edges = len(sub.get("edges", []))
    parts = [f"Investigating {focus}: connected to {n_nodes - 1} entities via {n_edges} observed relationships."]
    if patterns:
        for p in patterns[:5]:
            parts.append(f"⚠ {p['pattern'].replace('_', ' ').title()} ({p['severity']}): {p['description']}")
    else:
        parts.append("No lateral-movement patterns matched yet at the current thresholds.")
    return " ".join(parts)
