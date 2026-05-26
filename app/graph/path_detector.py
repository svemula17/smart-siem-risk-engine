"""Pattern detectors that fire LateralMovementIncident rows from the live graph."""
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.graph.loader import graph_loader
from app.models.db_models import LateralMovementIncidentDB

logger = logging.getLogger(__name__)

# Thresholds — tune in UI later
FAN_OUT_HOST_THRESHOLD = 4        # 1 user/ip auth to >= N hosts
FAN_OUT_WINDOW_MIN = 30
PRIV_CHAIN_MAX_HOPS = 3
BEACON_MIN_HITS = 8


def _now():
    return datetime.utcnow()


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", ""))
    except Exception:
        return None


def _save_incident(db: Session, pattern: str, severity: str, path: List[str],
                   alert_ids: List[str], description: str) -> Optional[LateralMovementIncidentDB]:
    # dedupe: skip if identical open incident exists in last hour
    cutoff = (_now() - timedelta(hours=1)).isoformat()
    existing = (
        db.query(LateralMovementIncidentDB)
        .filter(
            LateralMovementIncidentDB.pattern == pattern,
            LateralMovementIncidentDB.status == "open",
            LateralMovementIncidentDB.created_at > cutoff,
        )
        .all()
    )
    path_json = json.dumps(path)
    for e in existing:
        if e.path_json == path_json:
            return None

    row = LateralMovementIncidentDB(
        pattern=pattern,
        severity=severity,
        path_json=path_json,
        node_count=len(path),
        alert_ids_json=json.dumps(alert_ids[-25:]),
        description=description,
        status="open",
        created_at=_now().isoformat(),
    )
    db.add(row)
    try:
        db.commit()
        logger.info(f"[graph] {pattern} incident #{row.id}: {description}")
        return row
    except Exception as e:
        logger.warning(f"[graph] incident save failed: {e}")
        db.rollback()
        return None


def detect_fan_out_auth(db: Session, focus_keys: List[str]) -> List[LateralMovementIncidentDB]:
    """User or IP that authenticated to >= N distinct hosts in a recent window."""
    g = graph_loader.graph
    if g is None:
        return []
    cutoff = _now() - timedelta(minutes=FAN_OUT_WINDOW_MIN)
    incidents = []
    for key in focus_keys:
        if key not in g:
            continue
        ntype = g.nodes[key].get("node_type")
        if ntype not in ("user", "ip"):
            continue
        hosts = set()
        alert_ids = []
        for _, dst, edata in g.out_edges(key, data=True):
            if edata.get("relation") != "authenticated_to":
                continue
            ls = _parse_ts(edata.get("last_seen"))
            if ls and ls < cutoff:
                continue
            if g.nodes[dst].get("node_type") == "host" or g.nodes[dst].get("node_type") == "ip":
                hosts.add(dst)
                rid = edata.get("raw_alert_id")
                if rid:
                    alert_ids.append(rid)
        if len(hosts) >= FAN_OUT_HOST_THRESHOLD:
            path = [key] + list(hosts)
            inc = _save_incident(
                db, "fan_out_auth", "High", path, alert_ids,
                f"{g.nodes[key].get('value')} authenticated to {len(hosts)} distinct hosts in {FAN_OUT_WINDOW_MIN}m",
            )
            if inc:
                incidents.append(inc)
    return incidents


def detect_privilege_chain(db: Session, focus_keys: List[str]) -> List[LateralMovementIncidentDB]:
    """Path of length <= N from a non-privileged user to a privileged host/user."""
    import networkx as nx
    g = graph_loader.graph
    if g is None:
        return []
    incidents = []
    # Targets: privileged nodes
    priv_targets = [k for k, d in g.nodes(data=True) if d.get("tier") == "privileged"]
    if not priv_targets:
        return []
    for key in focus_keys:
        if key not in g:
            continue
        ntier = g.nodes[key].get("tier")
        if ntier == "privileged":
            continue
        if g.nodes[key].get("node_type") not in ("user", "ip"):
            continue
        for target in priv_targets:
            if target == key:
                continue
            try:
                paths = list(nx.all_simple_paths(g, key, target, cutoff=PRIV_CHAIN_MAX_HOPS))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                paths = []
            if not paths:
                continue
            path = paths[0]
            inc = _save_incident(
                db, "privilege_chain", "Critical", path, [],
                f"Path from {g.nodes[key].get('value')} → {g.nodes[target].get('value')} via {len(path)-1} hops",
            )
            if inc:
                incidents.append(inc)
            break  # one chain per focus is enough
    return incidents


def detect_beacon(db: Session, focus_keys: List[str]) -> List[LateralMovementIncidentDB]:
    """Repeated connected_to edges to the same external destination."""
    g = graph_loader.graph
    if g is None:
        return []
    incidents = []
    for key in focus_keys:
        if key not in g:
            continue
        if g.nodes[key].get("node_type") != "ip":
            continue
        for _, dst, edata in g.out_edges(key, data=True):
            if edata.get("relation") != "connected_to":
                continue
            cnt = edata.get("count", 1)
            dst_tier = g.nodes[dst].get("tier")
            if cnt >= BEACON_MIN_HITS and dst_tier == "external":
                inc = _save_incident(
                    db, "beacon", "High", [key, dst], [],
                    f"{g.nodes[key].get('value')} connected to external {g.nodes[dst].get('value')} {cnt}× — possible C2 beacon",
                )
                if inc:
                    incidents.append(inc)
    return incidents


def detect_tier_cross(db: Session, focus_keys: List[str]) -> List[LateralMovementIncidentDB]:
    """An edge that crosses external → internal or user → privileged."""
    g = graph_loader.graph
    if g is None:
        return []
    incidents = []
    for key in focus_keys:
        if key not in g:
            continue
        src_tier = g.nodes[key].get("tier")
        for _, dst, edata in g.out_edges(key, data=True):
            dst_tier = g.nodes[dst].get("tier")
            crossed = False
            if src_tier == "external" and dst_tier in ("internal", "privileged"):
                crossed = True
            if src_tier == "user" and dst_tier == "privileged":
                crossed = True
            if crossed and edata.get("count", 1) >= 2:
                rid = edata.get("raw_alert_id")
                inc = _save_incident(
                    db, "tier_cross", "High", [key, dst], [rid] if rid else [],
                    f"Tier boundary crossed: {src_tier or '?'} → {dst_tier or '?'} ({g.nodes[key].get('value')} → {g.nodes[dst].get('value')})",
                )
                if inc:
                    incidents.append(inc)
    return incidents


def detect_patterns(db: Session, focus_node_keys: List[str]) -> List[Dict[str, Any]]:
    """Run all pattern detectors centred on the given recently-touched nodes."""
    if not graph_loader.available or graph_loader.graph is None:
        return []
    try:
        from app.graph.rules_seed import is_pattern_active
    except Exception:
        is_pattern_active = lambda _db, _p: True
    all_incidents = []
    pattern_map = {
        "fan_out_auth": detect_fan_out_auth,
        "privilege_chain": detect_privilege_chain,
        "beacon": detect_beacon,
        "tier_cross": detect_tier_cross,
    }
    for pat, fn in pattern_map.items():
        if not is_pattern_active(db, pat):
            continue
        try:
            for inc in fn(db, focus_node_keys):
                all_incidents.append({
                    "id": inc.id,
                    "pattern": inc.pattern,
                    "severity": inc.severity,
                    "description": inc.description,
                    "path": json.loads(inc.path_json),
                })
        except Exception as e:
            logger.warning(f"[graph] detector {fn.__name__} failed: {e}")
    return all_incidents
