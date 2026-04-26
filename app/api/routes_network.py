"""
Network Intelligence Routes — Subnet behavior analysis, IP reputation scoring.
"""
from collections import Counter, defaultdict
from fastapi import APIRouter

import httpx

from app.database import SessionLocal
from app.models.db_models import (
    BlockedIPDB, IOCDB, IPEntityProfileDB,
    NormalizedAlertDB, ScoredAlertDB,
)

router = APIRouter()

# In-memory cache for GeoIP lookups: ip -> {country, country_code, lat, lon, city}
_GEOIP_CACHE: dict = {}


def _subnet(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3]) + ".0/24"
    return ip + ".0/24"


@router.get("/api/v1/network/behavior")
def get_network_behavior():
    """Aggregate UEBA profiles and alert activity by /24 subnet."""
    db = SessionLocal()
    try:
        # Load all UEBA profiles
        profiles = db.query(IPEntityProfileDB).all()

        subnet_stats: dict = defaultdict(lambda: {
            "alert_count": 0,
            "total_risk": 0,
            "ueba_score": 0,
            "ips": set(),
            "levels": [],
        })

        for p in profiles:
            sn = _subnet(p.ip_address)
            subnet_stats[sn]["ips"].add(p.ip_address)
            subnet_stats[sn]["ueba_score"] += p.cumulative_risk_score
            subnet_stats[sn]["levels"].append(p.risk_level)
            subnet_stats[sn]["alert_count"] += p.total_alerts_seen
            subnet_stats[sn]["total_risk"] += p.cumulative_risk_score

        # Sort by ueba_score descending
        sorted_subnets = sorted(
            subnet_stats.items(), key=lambda x: -x[1]["ueba_score"]
        )[:10]

        top_segments = []
        for sn, stats in sorted_subnets:
            avg_risk = round(stats["total_risk"] / max(len(stats["ips"]), 1))
            levels = stats["levels"]
            verdict = (
                "Critical" if "Critical" in levels
                else "High" if "High" in levels
                else "Medium" if "Medium" in levels
                else "Low"
            )
            top_segments.append({
                "subnet": sn,
                "alert_count": stats["alert_count"],
                "avg_risk": min(avg_risk, 100),
                "ueba_score": stats["ueba_score"],
                "unique_ips": len(stats["ips"]),
                "verdict": verdict,
            })

        # KPI aggregates
        total_profiles = len(profiles)
        ueba_flagged = sum(
            1 for p in profiles if p.risk_level in ("High", "Critical")
        )
        suspicious_segments = sum(
            1 for _, s in sorted_subnets if s["ueba_score"] > 50
        )
        unique_attackers = len({p.ip_address for p in profiles if p.risk_level != "Low"})
        network_risk = min(100, round(
            sum(p.cumulative_risk_score for p in profiles) / max(total_profiles, 1) / 5
        ))

        # Covered MITRE TTPs (from recent alerts)
        norm_rows = db.query(NormalizedAlertDB.mitre_ids_json).limit(5000).all()
        covered_ttps = set()
        for (mj,) in norm_rows:
            try:
                import json
                ttps = json.loads(mj) if mj else []
                covered_ttps.update(ttps)
            except Exception:
                pass

        return {
            "suspicious_segments": suspicious_segments,
            "unique_attackers": unique_attackers,
            "network_risk_score": network_risk,
            "ueba_flagged": ueba_flagged,
            "total_profiles": total_profiles,
            "top_segments": top_segments,
            "covered_ttps": list(covered_ttps),
        }
    finally:
        db.close()


@router.get("/api/v1/network/ip-reputation")
def get_ip_reputation(ip: str):
    """
    Compute a synthetic 0–100 reputation score for an IP.
    Uses IOC DB, BlockedIPDB, and UEBA profiles (no external API calls).
    """
    db = SessionLocal()
    try:
        score = 10
        label = "Clean"
        details_parts = []

        # Check IOC
        ioc = db.query(IOCDB).filter(
            IOCDB.value == ip, IOCDB.is_active == True, IOCDB.ioc_type == "ip"
        ).first()
        if ioc:
            score = max(score, 88 if ioc.severity == "Critical" else 75)
            label = "Malicious"
            details_parts.append(f"IOC match: {ioc.description or ioc.source or 'threat feed'} [{ioc.severity}]")

        # Check BlockedIPDB
        blocked = db.query(BlockedIPDB).filter(BlockedIPDB.ip_address == ip).first()
        if blocked:
            score = max(score, 72)
            label = label if label == "Malicious" else "Blocked"
            details_parts.append(f"Blocked: {blocked.reason}")

        # Check UEBA
        ueba = db.query(IPEntityProfileDB).filter(
            IPEntityProfileDB.ip_address == ip
        ).first()
        if ueba:
            if ueba.risk_level == "Critical":
                score = max(score, 90)
                label = "Malicious"
            elif ueba.risk_level == "High":
                score = max(score, 68)
                label = label if label == "Malicious" else "Suspicious"
            elif ueba.risk_level == "Medium":
                score = max(score, 42)
                label = label if label in ("Malicious", "Suspicious") else "Watchlist"
            details_parts.append(
                f"UEBA: {ueba.risk_level} ({ueba.total_alerts_seen} alerts, "
                f"cumulative risk {ueba.cumulative_risk_score})"
            )

        if not details_parts:
            details_parts.append("No known threats. IP appears clean in local intelligence.")

        return {
            "ip": ip,
            "score": score,
            "label": label,
            "country": "—",   # no external GeoIP call here (use cached if available)
            "details": " | ".join(details_parts),
        }
    finally:
        db.close()


def _is_public_ip(ip: str) -> bool:
    if not ip or "." not in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0]); b = int(parts[1])
    except ValueError:
        return False
    if a == 10 or a == 127 or a == 0 or a >= 224:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


def _lookup_geoip(ip: str) -> dict:
    if ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[ip]
    result = {"ip": ip, "country": "Unknown", "country_code": "??", "lat": None, "lon": None, "city": None}
    if not _is_public_ip(ip):
        result["country"] = "Private"
        result["country_code"] = "RFC1918"
        _GEOIP_CACHE[ip] = result
        return result
    try:
        r = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon"},
            timeout=2.5,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                result.update({
                    "country": d.get("country") or "Unknown",
                    "country_code": d.get("countryCode") or "??",
                    "lat": d.get("lat"),
                    "lon": d.get("lon"),
                    "city": d.get("city"),
                })
    except Exception:
        pass
    _GEOIP_CACHE[ip] = result
    return result


@router.get("/api/v1/network/geoip")
def get_geoip_map(top: int = 30):
    """Aggregate top source IPs and resolve them to coordinates for the map."""
    db = SessionLocal()
    try:
        rows = db.query(NormalizedAlertDB.source_ip).filter(
            NormalizedAlertDB.source_ip.isnot(None)
        ).limit(20000).all()
        counts: Counter = Counter(ip for (ip,) in rows if ip)
        top_ips = counts.most_common(top)

        points = []
        country_counts: Counter = Counter()
        for ip, n in top_ips:
            geo = _lookup_geoip(ip)
            country_counts[geo["country"]] += n
            if geo.get("lat") is not None:
                points.append({
                    "ip": ip,
                    "alert_count": n,
                    "country": geo["country"],
                    "country_code": geo["country_code"],
                    "city": geo.get("city"),
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                })
        return {
            "total_unique_ips": len(counts),
            "resolved_points": len(points),
            "points": points,
            "top_countries": [
                {"country": c, "alerts": n}
                for c, n in country_counts.most_common(10)
            ],
        }
    finally:
        db.close()
