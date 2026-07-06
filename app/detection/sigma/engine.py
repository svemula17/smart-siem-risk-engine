"""Sigma engine: rule storage, caching, and pipeline application.

Bundled rules under rules/sigma/*.yml are synced into the sigma_rules table
at first use; analysts can upload more via the API. Matches boost the alert's
risk score by level and are recorded in sigma_matches.
"""
import json
import logging
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.detection.sigma import evaluator
from app.detection.sigma.field_map import build_event
from app.detection.sigma.parser import SigmaParseError, SigmaRule, parse_rule
from app.models.db_models import SigmaMatchDB, SigmaRuleDB

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "sigma"

LEVEL_BOOST = {"informational": 0, "low": 5, "medium": 10, "high": 20, "critical": 30}


class SigmaEngine:
    def __init__(self):
        self._cache: list[SigmaRule] | None = None
        self._synced = False

    # ── rule loading ──────────────────────────────────────────────────────────

    def sync_bundled_rules(self, db: Session) -> int:
        """Load rules/sigma/*.yml into the DB once (no overwrite of uploads)."""
        count = 0
        if not RULES_DIR.is_dir():
            return 0
        for path in sorted(RULES_DIR.glob("*.yml")):
            try:
                rule = parse_rule(path.read_text())
            except SigmaParseError as e:
                logger.warning(f"[sigma] skipping {path.name}: {e}")
                continue
            if db.query(SigmaRuleDB).filter_by(rule_uid=rule.rule_uid).first():
                continue
            db.add(SigmaRuleDB(
                rule_uid=rule.rule_uid,
                title=rule.title,
                level=rule.level,
                tags_json=json.dumps(rule.tags),
                yaml_text=rule.yaml_text,
                source="bundled",
                is_active=True,
                created_at=datetime.utcnow().isoformat(),
            ))
            count += 1
        if count:
            db.commit()
            logger.info(f"[sigma] synced {count} bundled rules")
        return count

    def load_active_rules(self, db: Session) -> list[SigmaRule]:
        if not self._synced:
            self.sync_bundled_rules(db)
            self._synced = True
        rows = db.query(SigmaRuleDB).filter(SigmaRuleDB.is_active == True).all()
        rules = []
        for row in rows:
            try:
                rules.append(parse_rule(row.yaml_text))
            except SigmaParseError as e:
                logger.warning(f"[sigma] rule {row.rule_uid} unparseable: {e}")
        self._cache = rules
        return rules

    def invalidate_cache(self):
        self._cache = None

    # ── pipeline hook ─────────────────────────────────────────────────────────

    def apply(self, db: Session, raw_alert, normalized, scored) -> list[SigmaRule]:
        """Evaluate active rules; boost score and record matches. Returns matches."""
        rules = self._cache if self._cache is not None else self.load_active_rules(db)
        if not rules:
            return []

        event = build_event(raw_alert, normalized)
        matches = []
        for rule in rules:
            try:
                if evaluator.evaluate(rule, event):
                    matches.append(rule)
            except Exception as e:
                logger.debug(f"[sigma] rule {rule.rule_uid} evaluation error: {e}")

        for rule in matches:
            boost = LEVEL_BOOST.get(rule.level, 10)
            scored.risk_score = min(100, scored.risk_score + boost)
            scored.score_reasons.append(f"Sigma: {rule.title} [{rule.level}] (+{boost})")
            db.add(SigmaMatchDB(
                rule_uid=rule.rule_uid,
                rule_title=rule.title,
                level=rule.level,
                raw_alert_id=normalized.alert_id,
                matched_at=datetime.utcnow().isoformat(),
            ))
        if matches:
            db.commit()
            # Re-derive the recommended action from the boosted score
            from app.scoring.score_helpers import get_recommended_action
            scored.recommended_action = get_recommended_action(scored.risk_score)
        return matches


sigma_engine = SigmaEngine()
