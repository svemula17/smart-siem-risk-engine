"""Multi-event correlation engine.

Rule types (stored as JSON in correlation_rules.logic_json):

- mitre_tactic: single-alert match on a MITRE technique + minimum risk.
    {"type": "mitre_tactic", "mitre_id": "T1110", "min_risk": 80}

- threshold: N matching alerts from the same entity inside a time window.
    {"type": "threshold", "attack_type": "Brute Force", "group_by": "source_ip",
     "threshold": 5, "window_minutes": 10, "min_risk": 0}

- sequence: attack type A followed by attack type B from the same entity
  inside a window (e.g. recon then exfiltration).
    {"type": "sequence", "first": "Reconnaissance", "then": "Data Exfiltration",
     "group_by": "source_ip", "window_minutes": 60}

- ioc_plus: alert source IP matches an active IOC AND risk is at least X.
    {"type": "ioc_plus", "min_risk": 60}

Matches open an incident. Re-matches for the same (rule, entity) append the
alert to the open incident instead of creating duplicates.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.db_models import CorrelationRuleDB, IncidentDB, NormalizedAlertDB, ScoredAlertDB
from app.models.normalized_alert import NormalizedAlert
from app.models.scored_alert import ScoredAlert
from app.services.incident_service import add_timeline_event, create_incident

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self):
        self.active_rules = []

    def load_rules(self, db: Session):
        """Loads active rules from DB into memory for fast evaluation."""
        self.active_rules = db.query(CorrelationRuleDB).filter(CorrelationRuleDB.is_active == True).all()
        logger.info(f"Loaded {len(self.active_rules)} active correlation rules.")

    def evaluate_alert(self, db: Session, scored_alert: ScoredAlert, normalized_alert: NormalizedAlert):
        """Evaluate a newly scored alert against active rules."""
        if not self.active_rules:
            self.load_rules(db)

        for rule in self.active_rules:
            try:
                logic = json.loads(rule.logic_json)
                self._check_rule(db, rule, logic, scored_alert, normalized_alert)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")

    # ── rule dispatch ─────────────────────────────────────────────────────────

    def _check_rule(self, db: Session, rule: CorrelationRuleDB, logic: dict[str, Any],
                    scored: ScoredAlert, norm: NormalizedAlert):
        rule_type = logic.get("type", "")
        if rule_type == "mitre_tactic":
            self._check_mitre_tactic(db, rule, logic, scored, norm)
        elif rule_type == "threshold":
            self._check_threshold(db, rule, logic, scored, norm)
        elif rule_type == "sequence":
            self._check_sequence(db, rule, logic, scored, norm)
        elif rule_type == "ioc_plus":
            self._check_ioc_plus(db, rule, logic, scored, norm)

    def _check_mitre_tactic(self, db, rule, logic, scored, norm):
        mitre_target = logic.get("mitre_id", "")
        mitre_ids = norm.mitre_ids or []
        if mitre_target in mitre_ids and scored.risk_score >= logic.get("min_risk", 80):
            self._open_or_append(
                db, rule,
                entity=norm.source_ip or "unknown",
                alert_id=scored.alert_id,
                title=f"{rule.name} detected from {norm.source_ip}",
                description=f"Correlation rule '{rule.name}' triggered on MITRE technique {mitre_target}.",
            )

    def _check_threshold(self, db, rule, logic, scored, norm):
        entity = self._entity_value(norm, logic.get("group_by", "source_ip"))
        if not entity:
            return
        if scored.risk_score < logic.get("min_risk", 0):
            return
        attack_type = logic.get("attack_type")
        if attack_type and (norm.attack_type or "") != attack_type:
            return

        window_min = logic.get("window_minutes", 10)
        threshold = logic.get("threshold", 5)
        cutoff = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat()

        q = (
            db.query(NormalizedAlertDB)
            .join(ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id)
            .filter(NormalizedAlertDB.source_ip == entity)
            .filter(ScoredAlertDB.processed_at >= cutoff)
        )
        if attack_type:
            q = q.filter(NormalizedAlertDB.attack_type == attack_type)
        count = q.count() + 1  # +1: the current alert isn't persisted yet

        if count >= threshold:
            self._open_or_append(
                db, rule, entity=entity, alert_id=scored.alert_id,
                title=f"{rule.name}: {count} events from {entity} in {window_min}m",
                description=(
                    f"Threshold correlation '{rule.name}' fired — {count} matching alerts "
                    f"from {entity} within {window_min} minutes (threshold {threshold})."
                ),
            )

    def _check_sequence(self, db, rule, logic, scored, norm):
        entity = self._entity_value(norm, logic.get("group_by", "source_ip"))
        if not entity:
            return
        first, then = logic.get("first"), logic.get("then")
        if not first or not then or (norm.attack_type or "") != then:
            return

        window_min = logic.get("window_minutes", 60)
        cutoff = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat()
        prior = (
            db.query(NormalizedAlertDB)
            .join(ScoredAlertDB, NormalizedAlertDB.raw_alert_id == ScoredAlertDB.raw_alert_id)
            .filter(NormalizedAlertDB.source_ip == entity)
            .filter(NormalizedAlertDB.attack_type == first)
            .filter(ScoredAlertDB.processed_at >= cutoff)
            .first()
        )
        if prior:
            self._open_or_append(
                db, rule, entity=entity, alert_id=scored.alert_id,
                title=f"{rule.name}: {first} → {then} from {entity}",
                description=(
                    f"Sequence correlation '{rule.name}' fired — '{first}' followed by "
                    f"'{then}' from {entity} within {window_min} minutes."
                ),
            )

    def _check_ioc_plus(self, db, rule, logic, scored, norm):
        if not norm.source_ip or scored.risk_score < logic.get("min_risk", 60):
            return
        from app.services.ioc_manager import check_ip_against_ioc
        ioc = check_ip_against_ioc(db, norm.source_ip)
        if ioc:
            self._open_or_append(
                db, rule, entity=norm.source_ip, alert_id=scored.alert_id,
                title=f"{rule.name}: IOC-listed {norm.source_ip} active at risk {scored.risk_score}",
                description=(
                    f"IOC correlation '{rule.name}' fired — {norm.source_ip} matches active IOC "
                    f"({ioc.get('source')}: {ioc.get('description') or ioc.get('severity')}) "
                    f"with alert risk {scored.risk_score}."
                ),
            )

    # ── incident dedupe ───────────────────────────────────────────────────────

    def _open_or_append(self, db: Session, rule, entity: str, alert_id: str,
                        title: str, description: str):
        rule_key = f"corr:{rule.id}"
        existing = (
            db.query(IncidentDB)
            .filter(IncidentDB.rule_key == rule_key, IncidentDB.entity_key == entity)
            .filter(IncidentDB.status != "Closed")
            .first()
        )
        if existing:
            alert_ids = json.loads(existing.alerts_json or "[]")
            if alert_id not in alert_ids:
                alert_ids.append(alert_id)
                existing.alerts_json = json.dumps(alert_ids)
                existing.updated_at = datetime.utcnow().isoformat()
                db.commit()
                add_timeline_event(db, existing.id, f"Correlated alert {alert_id} appended by rule '{rule.name}'.")
            return existing

        logger.info(f"Rule '{rule.name}' opened incident for entity {entity}")
        incident = create_incident(db, title=title, description=description,
                                   severity=rule.severity, alert_ids=[alert_id])
        incident.rule_key = rule_key
        incident.entity_key = entity
        db.commit()
        return incident

    @staticmethod
    def _entity_value(norm: NormalizedAlert, group_by: str):
        if group_by == "username":
            return getattr(norm, "username", None)
        return norm.source_ip


# Singleton
correlation_engine = CorrelationEngine()
