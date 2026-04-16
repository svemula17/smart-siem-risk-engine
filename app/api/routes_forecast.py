"""
Threat Forecast Routes — Linear regression on 30-day alert trend to predict next 7 days.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter

from app.database import SessionLocal
from app.models.db_models import NormalizedAlertDB, ScoredAlertDB

router = APIRouter()

ATTACK_WEIGHTS = {
    "Brute Force": 0.28, "Reconnaissance": 0.10, "Credential Theft": 0.09,
    "Exploitation": 0.08, "Privilege Escalation": 0.08, "DDoS Attack": 0.07,
    "Lateral Movement": 0.07, "Data Exfiltration": 0.06, "Command & Control": 0.05,
    "Port Scanning": 0.04, "Unknown Threat": 0.08,
}


@router.get("/api/forecast/risk")
def get_risk_forecast():
    """Return 7-day linear regression forecast based on last 30 days of alert volume."""
    db = SessionLocal()
    try:
        # Pull 30-day daily totals
        cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
        rows = db.query(ScoredAlertDB.processed_at, ScoredAlertDB.risk_score).filter(
            ScoredAlertDB.processed_at >= cutoff
        ).limit(200000).all()

        daily: dict = defaultdict(int)
        for ts, _ in rows:
            day = str(ts)[:10]
            daily[day] += 1

        # Fill missing days with 0
        all_days = []
        base = datetime.utcnow() - timedelta(days=30)
        for i in range(30):
            d = (base + timedelta(days=i)).strftime("%Y-%m-%d")
            all_days.append(d)
            if d not in daily:
                daily[d] = 0

        sorted_days = sorted(all_days)
        y = [daily[d] for d in sorted_days]
        n = len(y)
        x = list(range(n))

        # Linear regression (numpy-free fallback)
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        denom = sum((xi - x_mean) ** 2 for xi in x)
        slope = (
            sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, y)) / denom
            if denom > 0 else 0.0
        )
        intercept = y_mean - slope * x_mean

        # R² confidence
        y_pred = [intercept + slope * xi for xi in x]
        ss_res = sum((yi - yp) ** 2 for yi, yp in zip(y, y_pred))
        ss_tot = sum((yi - y_mean) ** 2 for yi in y) or 1.0
        r2 = max(0.0, 1 - ss_res / ss_tot)

        # 7-day forecast
        last_date = datetime.strptime(sorted_days[-1], "%Y-%m-%d")
        forecast = []
        for i in range(1, 8):
            pred = max(0, round(intercept + slope * (n - 1 + i)))
            forecast.append({
                "day": (last_date + timedelta(days=i)).strftime("%Y-%m-%d"),
                "predicted": pred,
            })

        predicted_avg = round(sum(f["predicted"] for f in forecast) / 7)
        peak = max(forecast, key=lambda f: f["predicted"])

        trend = "up" if slope > 2 else "down" if slope < -2 else "stable"

        # Attack type breakdown (proportional forecast)
        attack_breakdown = [
            {
                "attack_type": at,
                "predicted": max(1, round(predicted_avg * w)),
                "pct": round(w * 100),
            }
            for at, w in sorted(ATTACK_WEIGHTS.items(), key=lambda x: -x[1])
            if at != "Unknown Threat"
        ]

        return {
            "trend": trend,
            "slope": round(slope, 3),
            "predicted_avg": predicted_avg,
            "predicted_peak": peak["predicted"],
            "peak_day": peak["day"],
            "confidence_pct": round(r2 * 100, 1),
            "historical": [{"day": d, "total": daily[d]} for d in sorted_days],
            "forecast": forecast,
            "attack_breakdown": attack_breakdown,
        }
    finally:
        db.close()
