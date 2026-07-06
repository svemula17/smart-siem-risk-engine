"""Shared per-alert processing pipeline.

Every ingestion path (demo driver run.py, REST API, syslog listener) funnels
raw alerts through process_raw_alert so scoring, response, correlation, UEBA,
graph extraction, and dashboard broadcast behave identically everywhere.
"""
import logging
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.evaluation.evaluator import evaluate_alert
from app.ingestion.validator import validate_raw_alert
from app.models.raw_alert import RawAlert
from app.normalization.mapper import normalize_alert
from app.response.responder import respond_to_alert
from app.scoring.scorer import score_alert
from app.services.alert_service import (
    save_normalized_alert,
    save_raw_alert,
    save_scored_alert,
)
from app.services.evaluation_service import save_evaluation_result

logger = logging.getLogger(__name__)


def build_broadcast_payload(alert, normalized, scored, is_anomaly: bool) -> dict:
    """Payload consumed by the dashboard WebSocket livefeed."""
    from app.services.geoip_service import geoip_engine

    lat = lon = country = city = None
    if normalized.source_ip:
        location = geoip_engine.get_location(normalized.source_ip)
        if location:
            lat, lon = location.get("lat"), location.get("lon")
            country, city = location.get("country"), location.get("city")

    alert_html = f"""
    <tr class="alert-row highlight-new">
        <td class="mono id-cell" title="New Alert">*Live*</td>
        <td class="mono id-cell" title="{alert.id}">{alert.id}</td>
        <td class="mono score-renderer" data-score="{scored.risk_score}">{scored.risk_score}/100</td>
        <td>
            <span class="badge badge-action badge-{scored.recommended_action.split('_')[0]}">
                {scored.recommended_action.replace('_', ' ')}
            </span>
        </td>
        <td style="color: var(--text-secondary); font-size: 0.8125rem;">
            {scored.action_taken.replace('_', ' ').title()}
        </td>
    </tr>
    """
    return {
        "alert_html": alert_html,
        "risk_score": scored.risk_score,
        "recommended_action": scored.recommended_action,
        "action_taken": scored.action_taken,
        "mitre_ids": normalized.mitre_ids,
        "attack_type": normalized.attack_type or "Unknown Threat",
        "lat": lat,
        "lon": lon,
        "country": country,
        "city": city,
        "is_anomaly": is_anomaly,
    }


def process_raw_alert(
    db: Session,
    alert: RawAlert,
    notify: Callable[[dict], None] | None = None,
    generate_report: bool = False,
):
    """Run one raw alert through the full detection pipeline.

    Returns (scored_alert, evaluation). When `notify` is given it receives the
    dashboard broadcast payload; exceptions from it are swallowed so a dead
    dashboard never stalls ingestion.
    """
    validate_raw_alert(alert)
    normalized = normalize_alert(alert)
    scored = score_alert(normalized)

    # ── ML anomaly boost (Isolation Forest) ──
    from app.services.ml_engine import ml_engine
    if not ml_engine.is_trained:
        ml_engine.train_on_history(db)

    is_anomaly = ml_engine.predict_anomaly(normalized, scored)
    if is_anomaly:
        scored.risk_score = min(100, scored.risk_score + 30)
        scored.score_reasons.append("ML Engine Auto-Triage: Isolation Forest Anomaly Detected")
        if scored.risk_score >= 80:
            scored.recommended_action = "block_and_report"
        elif scored.risk_score >= 60:
            scored.recommended_action = "generate_report"

    # ── Sigma detection rules ──
    try:
        from app.detection.sigma.engine import sigma_engine
        sigma_engine.apply(db, alert, normalized, scored)
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"[sigma] evaluation skipped: {e}")

    # ── SOAR response + evaluation ──
    scored = respond_to_alert(normalized, scored, db=db)
    evaluation = evaluate_alert(normalized, scored)

    save_raw_alert(db, alert)
    save_normalized_alert(db, normalized)
    save_scored_alert(db, scored)
    save_evaluation_result(db, evaluation)

    # ── Correlation + UEBA ──
    from app.services.correlation_engine import correlation_engine
    correlation_engine.evaluate_alert(db, scored, normalized)

    from app.services.ueba_engine import ueba_engine
    ueba_engine.update_profile(db, scored, normalized)

    # ── Attack graph ──
    try:
        from app.graph.extractor import extract_from_alert
        from app.graph.path_detector import detect_patterns
        extract_from_alert(db, normalized, scored)
        focus_keys = []
        if normalized.source_ip:
            focus_keys.append(f"ip:{normalized.source_ip}")
        if getattr(normalized, "username", None):
            focus_keys.append(f"user:{normalized.username}")
        if focus_keys:
            detect_patterns(db, focus_keys)
    except Exception as e:
        logger.debug(f"[graph] pipeline hook error: {e}")

    # ── Optional per-alert HTML report (demo driver behavior) ──
    if generate_report:
        try:
            from app.reporting.report_generator import generate_incident_report
            generate_incident_report(
                raw_alert=alert, normalized_alert=normalized,
                scored_alert=scored, evaluation=evaluation,
            )
        except Exception as e:
            logger.debug(f"[report] generation failed: {e}")

    # ── Dashboard broadcast + webhook notifications ──
    if notify:
        try:
            notify(build_broadcast_payload(alert, normalized, scored, is_anomaly))
        except Exception as e:
            logger.debug(f"[broadcast] notify failed: {e}")

    try:
        from app.response.notifications import notifier
        notifier.send_discord_alert({
            "alert_id": alert.id,
            "risk_score": scored.risk_score,
            "recommended_action": scored.recommended_action,
            "action_taken": scored.action_taken,
            "processed_at": scored.processed_at,
            "score_reasons": scored.score_reasons,
        }, alert.message)
    except Exception as e:
        logger.debug(f"[notify] webhook error: {e}")

    return scored, evaluation
