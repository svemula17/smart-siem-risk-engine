from sqlalchemy.orm import Session

from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.response.blocklist_manager import add_blocked_ip
from app.services.scoring_service import save_blocked_ip


import json
import logging
from sqlalchemy.orm import Session
from app.models.db_models import PlaybookDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.response.blocklist_manager import add_blocked_ip
from app.services.scoring_service import save_blocked_ip

logger = logging.getLogger(__name__)

class PlaybookEngine:
    def __init__(self):
        self.active_playbooks = []
        self._loaded = False

    def load_playbooks(self, db: Session):
        self.active_playbooks = db.query(PlaybookDB).filter(PlaybookDB.is_active == True).all()
        self._loaded = True

    def respond(self, normalized_alert: NormalizedAlert, scored_alert: ScoredAlert, db: Session | None = None) -> ScoredAlert:
        if db is not None and not self._loaded:
            self.load_playbooks(db)

        actions_taken = []

        # 1. Evaluate Dynamic Playbooks
        for playbook in self.active_playbooks:
            try:
                condition = json.loads(playbook.trigger_condition_json)
                
                # Check conditions
                match = True
                if "min_risk_score" in condition and scored_alert.risk_score < condition["min_risk_score"]:
                    match = False
                if "recommended_action" in condition and scored_alert.recommended_action != condition["recommended_action"]:
                    match = False
                
                if match:
                    actions = json.loads(playbook.actions_json)
                    for action in actions:
                        act_type = action.get("type")
                        if act_type == "block_ip" and normalized_alert.source_ip:
                            reason = action.get("reason", f"Playbook '{playbook.name}' triggered block.")
                            add_blocked_ip(normalized_alert.source_ip, reason, scored_alert.alert_id)
                            if db is not None:
                                save_blocked_ip(db, normalized_alert.source_ip, scored_alert.alert_id, reason, True)
                            actions_taken.append(f"blocked_{normalized_alert.source_ip}")
                        elif act_type == "notify":
                            # In a real system, send webhook here
                            actions_taken.append(f"notified_{action.get('channel', 'soc')}")
            except Exception as e:
                logger.error(f"Error executing playbook {playbook.name}: {e}")

        # 2. Fallback to hardcoded action mapped from scorer if no playbook specifically override or added
        if not actions_taken:
            action = scored_alert.recommended_action
            if action == "store_only":
                actions_taken.append("stored_only")
            elif action == "alert_only":
                actions_taken.append("alert_generated")
            elif action == "generate_report":
                actions_taken.append("report_queued")
            elif action == "block_and_report":
                if normalized_alert.source_ip:
                    reason = f"Risk score {scored_alert.risk_score} triggered block"
                    add_blocked_ip(normalized_alert.source_ip, reason, scored_alert.alert_id)
                    if db is not None:
                        save_blocked_ip(db, normalized_alert.source_ip, scored_alert.alert_id, reason, True)
                    actions_taken.append("ip_blocked_and_report_queued")
                else:
                    actions_taken.append("report_queued_no_ip_to_block")
            else:
                actions_taken.append("no_action")

        scored_alert.action_taken = ", ".join(actions_taken)
        return scored_alert

playbook_engine = PlaybookEngine()

def respond_to_alert(normalized_alert: NormalizedAlert, scored_alert: ScoredAlert, db: Session | None = None) -> ScoredAlert:
    return playbook_engine.respond(normalized_alert, scored_alert, db)