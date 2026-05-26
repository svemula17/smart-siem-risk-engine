"""In-memory networkx mirror of the persisted graph for fast traversal."""
import logging
import threading
from typing import Any, Dict, List, Optional

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    nx = None
    _HAS_NX = False

from app.database import SessionLocal
from app.models.db_models import GraphNodeDB, GraphEdgeDB

logger = logging.getLogger(__name__)


class GraphLoader:
    def __init__(self):
        self._lock = threading.RLock()
        self._g = nx.MultiDiGraph() if _HAS_NX else None
        self._ready = False
        self._node_by_id: Dict[int, Dict[str, Any]] = {}

    @property
    def available(self) -> bool:
        return _HAS_NX

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def graph(self):
        return self._g

    def warm(self) -> int:
        """Load entire persisted graph into memory. Idempotent."""
        if not _HAS_NX:
            return 0
        with self._lock:
            self._g = nx.MultiDiGraph()
            self._node_by_id = {}
            db = SessionLocal()
            try:
                nodes = db.query(GraphNodeDB).all()
                for n in nodes:
                    key = self._key(n.node_type, n.value)
                    attrs = {
                        "id": n.id,
                        "node_type": n.node_type,
                        "value": n.value,
                        "tier": n.tier,
                        "risk_score": n.risk_score,
                        "first_seen": n.first_seen,
                        "last_seen": n.last_seen,
                    }
                    self._g.add_node(key, **attrs)
                    self._node_by_id[n.id] = attrs

                edges = db.query(GraphEdgeDB).all()
                for e in edges:
                    src = self._node_by_id.get(e.src_node_id)
                    dst = self._node_by_id.get(e.dst_node_id)
                    if not src or not dst:
                        continue
                    self._g.add_edge(
                        self._key(src["node_type"], src["value"]),
                        self._key(dst["node_type"], dst["value"]),
                        key=e.relation,
                        relation=e.relation,
                        weight=e.weight,
                        count=e.count,
                        last_seen=e.last_seen,
                        first_seen=e.first_seen,
                        raw_alert_id=e.raw_alert_id,
                    )
                self._ready = True
                logger.info(f"[graph] loaded {self._g.number_of_nodes()} nodes / {self._g.number_of_edges()} edges")
                return self._g.number_of_nodes()
            finally:
                db.close()

    def apply_delta(self, nodes: Dict[str, Any], edges: List[Any], relation: str):
        """Merge a small set of nodes/edges produced by the extractor into the live graph."""
        if not _HAS_NX or self._g is None:
            return
        with self._lock:
            for n in nodes.values():
                if n is None:
                    continue
                key = self._key(n.node_type, n.value)
                attrs = {
                    "id": n.id,
                    "node_type": n.node_type,
                    "value": n.value,
                    "tier": n.tier,
                    "risk_score": n.risk_score,
                    "first_seen": n.first_seen,
                    "last_seen": n.last_seen,
                }
                self._g.add_node(key, **attrs)
                self._node_by_id[n.id] = attrs

            for e in edges:
                if e is None:
                    continue
                src = self._node_by_id.get(e.src_node_id)
                dst = self._node_by_id.get(e.dst_node_id)
                if not src or not dst:
                    continue
                self._g.add_edge(
                    self._key(src["node_type"], src["value"]),
                    self._key(dst["node_type"], dst["value"]),
                    key=e.relation,
                    relation=e.relation,
                    weight=e.weight,
                    count=e.count,
                    last_seen=e.last_seen,
                    first_seen=e.first_seen,
                    raw_alert_id=e.raw_alert_id,
                )

    @staticmethod
    def _key(node_type: str, value: str) -> str:
        return f"{node_type}:{value}"

    def neighborhood(self, node_type: str, value: str, depth: int = 1, cap: int = 200) -> Dict[str, Any]:
        """Return subgraph within `depth` hops, capped at `cap` nodes."""
        if not _HAS_NX or self._g is None:
            return {"nodes": [], "edges": []}
        with self._lock:
            key = self._key(node_type, value)
            if key not in self._g:
                return {"nodes": [], "edges": []}
            # BFS in undirected projection for visualization
            undirected = self._g.to_undirected(as_view=True)
            visited = {key}
            frontier = {key}
            for _ in range(max(1, depth)):
                nxt = set()
                for n in frontier:
                    nxt.update(undirected.neighbors(n))
                visited.update(nxt)
                frontier = nxt - visited if False else nxt
                if len(visited) >= cap:
                    break
            visited = set(list(visited)[:cap])
            sub = self._g.subgraph(visited)
            return self._serialize(sub, focus=key)

    def shortest_paths(self, src_key: str, dst_key: str, max_depth: int = 4, max_paths: int = 5):
        if not _HAS_NX or self._g is None:
            return []
        with self._lock:
            if src_key not in self._g or dst_key not in self._g:
                return []
            try:
                paths = []
                gen = nx.all_simple_paths(self._g, src_key, dst_key, cutoff=max_depth)
                for p in gen:
                    paths.append(p)
                    if len(paths) >= max_paths:
                        break
                return paths
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return []

    def serialize_full(self, limit: int = 500) -> Dict[str, Any]:
        if not _HAS_NX or self._g is None:
            return {"nodes": [], "edges": []}
        with self._lock:
            if self._g.number_of_nodes() <= limit:
                return self._serialize(self._g)
            # rank by risk_score desc
            ranked = sorted(
                self._g.nodes(data=True),
                key=lambda n: n[1].get("risk_score", 0),
                reverse=True,
            )[:limit]
            keep = {k for k, _ in ranked}
            sub = self._g.subgraph(keep)
            return self._serialize(sub)

    def _serialize(self, g, focus: Optional[str] = None) -> Dict[str, Any]:
        nodes = []
        for k, data in g.nodes(data=True):
            nodes.append({
                "id": k,
                "type": data.get("node_type"),
                "value": data.get("value"),
                "tier": data.get("tier"),
                "risk_score": data.get("risk_score", 0),
                "last_seen": data.get("last_seen"),
                "focus": k == focus,
            })
        edges = []
        for u, v, key, data in g.edges(keys=True, data=True):
            edges.append({
                "source": u,
                "target": v,
                "relation": data.get("relation", key),
                "count": data.get("count", 1),
                "weight": data.get("weight", 1.0),
                "last_seen": data.get("last_seen"),
            })
        return {"nodes": nodes, "edges": edges}

    def stats(self) -> Dict[str, Any]:
        if not _HAS_NX or self._g is None:
            return {"available": _HAS_NX, "ready": False, "nodes": 0, "edges": 0}
        with self._lock:
            return {
                "available": True,
                "ready": self._ready,
                "nodes": self._g.number_of_nodes(),
                "edges": self._g.number_of_edges(),
            }


graph_loader = GraphLoader()
