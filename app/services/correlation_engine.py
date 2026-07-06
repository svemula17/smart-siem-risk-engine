import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.db_models import CorrelationRuleDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.services.incident_service import create_incident

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.active_rules = []

    def load_rules(self, db: Session):
        """Loads active rules from DB into memory for fast evaluation."""
        self.active_rules = db.query(CorrelationRuleDB).filter(CorrelationRuleDB.is_active == True).all()
        logger.info(f"Loaded {len(self.active_rules)} active correlation rules.")

    def evaluate_alert(self, db: Session, scored_alert: ScoredAlert, normalized_alert: NormalizedAlert):
        """
        Evaluates a newly scored alert against active rules.
        If a rule matches, creates or updates an incident.
        """
        if not self.active_rules:
            self.load_rules(db)

        # In a real engine, this would use a complex in-memory windowing system (like Apache Flink)
        # For this simulation, we'll do query-based retroactive correlation.

        try:
            norm_payload = normalized_alert.model_dump()
        except Exception:
            norm_payload = {}

        for rule in self.active_rules:
            try:
                logic = json.loads(rule.logic_json)
                self._check_rule(db, rule, logic, scored_alert, normalized_alert, norm_payload)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")

    def _check_rule(self, db: Session, rule: CorrelationRuleDB, logic: dict[str, Any],
                    current_scored: ScoredAlert, current_norm: NormalizedAlert, current_payload: dict):

        # Example logic schema:
        # {
        #   "condition": "event_type == 'failed_login'",
        #   "threshold": 5,
        #   "window_minutes": 10,
        #   "group_by": "source_ip"
        # }

        # Simulated implementation matching "Brute Force" or similar basic rules
        condition_type = logic.get("type", "")

        if condition_type == "mitre_tactic":
            mitre_target = logic.get("mitre_id", "")
            mitre_ids_list = current_norm.mitre_ids if current_norm.mitre_ids else []
            if mitre_target in mitre_ids_list and current_scored.risk_score >= logic.get("min_risk", 80):

                logger.info(f"Rule '{rule.name}' triggered by alert {current_scored.alert_id}")

                title = f"{rule.name} detected from {current_norm.source_ip}"
                desc = f"Correlation rule '{rule.name}' triggered based on MITRE tactic {mitre_target}. "

                create_incident(
                    db=db,
                    title=title,
                    description=desc,
                    severity=rule.severity,
                    alert_ids=[current_scored.alert_id]
                )

# Singleton
correlation_engine = CorrelationEngine()
