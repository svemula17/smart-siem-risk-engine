import pytest

from app.detection.sigma.evaluator import evaluate
from app.detection.sigma.parser import SigmaParseError, parse_rule

BASE_EVENT = {
    "message": "ISCX Alert: PortScan",
    "source_ip": "203.0.113.9",
    "target_ip": "10.0.0.5",
    "category": "ids",
    "severity": 3,
    "attack_type": "Reconnaissance",
    "mitre_ids": ["T1046"],
    "username": "root",
}


def _rule(detection_yaml: str, level="medium") -> str:
    return f"title: Test Rule\nlevel: {level}\ndetection:\n{detection_yaml}"


# ── parser ─────────────────────────────────────────────────────────────────────

def test_parse_full_rule():
    rule = parse_rule(
        "title: My Rule\nid: abc-123\nlevel: high\ntags: [attack.t1046]\n"
        "detection:\n  selection:\n    attack_type: Reconnaissance\n  condition: selection\n"
    )
    assert rule.rule_uid == "abc-123"
    assert rule.level == "high"
    assert rule.tags == ["attack.t1046"]


@pytest.mark.parametrize("bad", [
    "not yaml: [unclosed",
    "title: X\n",  # no detection
    "title: X\ndetection:\n  selection:\n    a: b\n",  # no condition
    "detection:\n  selection:\n    a: b\n  condition: selection\n",  # no title
])
def test_parse_rejects_invalid(bad):
    with pytest.raises(SigmaParseError):
        parse_rule(bad)


# ── evaluator: table-driven ────────────────────────────────────────────────────

CASES = [
    # (detection yaml, expected)
    ("  selection:\n    attack_type: Reconnaissance\n  condition: selection", True),
    ("  selection:\n    attack_type: 'Brute Force'\n  condition: selection", False),
    ("  selection:\n    attack_type: reconnaissance\n  condition: selection", True),  # case-insensitive
    ("  selection:\n    message|contains: portscan\n  condition: selection", True),
    ("  selection:\n    message|startswith: 'ISCX'\n  condition: selection", True),
    ("  selection:\n    message|endswith: 'PortScan'\n  condition: selection", True),
    ("  selection:\n    message|re: 'port\\s?scan'\n  condition: selection", True),
    ("  selection:\n    message: 'ISCX*'\n  condition: selection", True),  # wildcard
    ("  selection:\n    severity: 3\n  condition: selection", True),
    ("  selection:\n    severity: 1\n  condition: selection", False),
    ("  selection:\n    mitre_ids: T1046\n  condition: selection", True),  # list field
    ("  selection:\n    mitre_ids: T9999\n  condition: selection", False),
    # value lists = OR
    ("  selection:\n    attack_type:\n      - 'Brute Force'\n      - Reconnaissance\n  condition: selection", True),
    # multiple fields = AND
    ("  selection:\n    attack_type: Reconnaissance\n    severity: 3\n  condition: selection", True),
    ("  selection:\n    attack_type: Reconnaissance\n    severity: 1\n  condition: selection", False),
    # keywords list (message search)
    ("  keywords:\n    - portscan\n    - nothing\n  condition: keywords", True),
    # boolean logic
    ("  a:\n    severity: 3\n  b:\n    attack_type: Malware\n  condition: a and b", False),
    ("  a:\n    severity: 3\n  b:\n    attack_type: Malware\n  condition: a or b", True),
    ("  a:\n    severity: 3\n  b:\n    attack_type: Malware\n  condition: a and not b", True),
    ("  a:\n    severity: 3\n  b:\n    attack_type: Malware\n  condition: not (a or b)", False),
    # quantifiers
    ("  sel_a:\n    severity: 3\n  sel_b:\n    attack_type: Malware\n  condition: 1 of sel_*", True),
    ("  sel_a:\n    severity: 3\n  sel_b:\n    attack_type: Malware\n  condition: all of sel_*", False),
    ("  sel_a:\n    severity: 3\n  sel_b:\n    mitre_ids: T1046\n  condition: all of them", True),
    # field aliases
    ("  selection:\n    src_ip: 203.0.113.9\n  condition: selection", True),
    ("  selection:\n    User: root\n  condition: selection", True),
]


@pytest.mark.parametrize("detection,expected", CASES)
def test_evaluator_cases(detection, expected):
    rule = parse_rule(_rule(detection))
    assert evaluate(rule, BASE_EVENT) is expected


def test_unknown_selection_in_condition_raises():
    rule = parse_rule(_rule("  selection:\n    severity: 3\n  condition: nonexistent"))
    with pytest.raises(ValueError):
        evaluate(rule, BASE_EVENT)


# ── engine: pipeline application ───────────────────────────────────────────────

def test_engine_boosts_score_and_records_match(db, raw_alerts, monkeypatch, tmp_path):
    import app.detection.sigma.engine as engine_mod
    from app.detection.sigma.engine import SigmaEngine
    from app.models.db_models import SigmaMatchDB, SigmaRuleDB
    from app.normalization.mapper import normalize_alert
    from app.scoring.scorer import score_alert

    monkeypatch.setattr(engine_mod, "RULES_DIR", tmp_path)  # no bundled rules

    from datetime import datetime
    db.add(SigmaRuleDB(
        rule_uid="t-match-all", title="Match Everything", level="high",
        tags_json="[]", source="upload", is_active=True,
        created_at=datetime.utcnow().isoformat(),
        yaml_text=(
            "title: Match Everything\nlevel: high\n"
            "detection:\n  selection:\n    event_type: network_signature_alert\n  condition: selection\n"
        ),
    ))
    db.commit()

    engine = SigmaEngine()
    alert = raw_alerts[0]
    norm = normalize_alert(alert)
    scored = score_alert(norm)
    before = scored.risk_score

    matches = engine.apply(db, alert, norm, scored)
    assert len(matches) == 1
    assert scored.risk_score == min(100, before + 20)
    assert any("Sigma: Match Everything" in r for r in scored.score_reasons)
    assert db.query(SigmaMatchDB).count() == 1


def test_bundled_rules_parse_and_sync(db):
    from app.detection.sigma.engine import SigmaEngine
    from app.models.db_models import SigmaRuleDB

    engine = SigmaEngine()
    synced = engine.sync_bundled_rules(db)
    assert synced >= 10
    assert db.query(SigmaRuleDB).count() == synced
    # second sync is a no-op
    assert engine.sync_bundled_rules(db) == 0
