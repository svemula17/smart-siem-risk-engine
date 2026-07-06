from app.normalization.mapper import normalize_alert


def test_normalize_preserves_identity(raw_alerts):
    for raw in raw_alerts:
        norm = normalize_alert(raw)
        assert norm.alert_id == raw.id
        assert norm.source == raw.source
        assert norm.raw_severity == raw.raw_severity
        assert norm.ground_truth_label == raw.ground_truth_label


def test_normalize_extracts_source_ip(raw_alerts):
    for raw in raw_alerts:
        norm = normalize_alert(raw)
        if raw.entity_ids.ip:
            assert norm.source_ip == raw.entity_ids.ip[0]


def test_normalize_produces_mitre_list(raw_alerts):
    for raw in raw_alerts:
        norm = normalize_alert(raw)
        assert isinstance(norm.mitre_ids, list)


def test_normalize_assigns_attack_type(raw_alerts):
    for raw in raw_alerts:
        norm = normalize_alert(raw)
        assert isinstance(norm.attack_type, str) and norm.attack_type
