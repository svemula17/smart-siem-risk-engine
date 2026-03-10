from sqlalchemy.orm import Session

from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.response.blocklist_manager import add_blocked_ip
from app.services.scoring_service import save_blocked_ip


def respond_to_alert(
    normalized_alert: NormalizedAlert,
    scored_alert: ScoredAlert,
    db: Session | None = None,
) -> ScoredAlert:
    action = scored_alert.recommended_action

    if action == "store_only":
        scored_alert.action_taken = "stored_only"

    elif action == "alert_only":
        scored_alert.action_taken = "alert_generated"

    elif action == "generate_report":
        scored_alert.action_taken = "report_queued"

    elif action == "block_and_report":
        if normalized_alert.source_ip:
            reason = f"Risk score {scored_alert.risk_score} triggered block"

            add_blocked_ip(
                ip_address=normalized_alert.source_ip,
                reason=reason,
                alert_id=scored_alert.alert_id,
            )

            if db is not None:
                save_blocked_ip(
                    db=db,
                    ip_address=normalized_alert.source_ip,
                    raw_alert_id=scored_alert.alert_id,
                    reason=reason,
                    is_simulated=True,
                )

            scored_alert.action_taken = "ip_blocked_and_report_queued"
        else:
            scored_alert.action_taken = "report_queued_no_ip_to_block"

    else:
        scored_alert.action_taken = "no_action"

    return scored_alert