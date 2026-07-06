from app.ingestion.syslog.cef import is_cef, parse_cef
from app.ingestion.syslog.mapper import map_syslog_to_raw_alert
from app.ingestion.syslog.parser import parse_syslog

RFC3164 = "<34>Oct 11 22:14:15 web01 sshd[2412]: Failed password for root from 203.0.113.9 port 22 ssh2"
RFC5424 = '<165>1 2026-07-06T22:14:15.003Z fw01 checkpoint 1234 ID47 - Connection dropped from 198.51.100.7'
CEF_LINE = (
    "<134>Feb  9 10:11:12 arcsight CEF:0|Palo Alto|PAN-OS|9.1|threat|Malware Download Blocked|9|"
    "src=203.0.113.50 dst=10.0.0.8 suser=jdoe request=http://evil.example/mal.exe"
)


# ── RFC 3164 ──────────────────────────────────────────────────────────────────

def test_parse_rfc3164():
    msg = parse_syslog(RFC3164)
    assert msg.version == "rfc3164"
    assert msg.facility == 4 and msg.severity == 2  # <34> = 4*8 + 2
    assert msg.host == "web01"
    assert msg.app == "sshd" and msg.pid == "2412"
    assert "Failed password" in msg.message


def test_parse_rfc5424():
    msg = parse_syslog(RFC5424)
    assert msg.version == "rfc5424"
    assert msg.facility == 20 and msg.severity == 5  # <165> = 20*8 + 5
    assert msg.host == "fw01"
    assert msg.app == "checkpoint"
    assert "Connection dropped" in msg.message


def test_parse_garbage_falls_back():
    msg = parse_syslog("completely unstructured line")
    assert msg.version == "raw"
    assert msg.message == "completely unstructured line"


# ── CEF ───────────────────────────────────────────────────────────────────────

def test_cef_detection_and_parse():
    assert is_cef(CEF_LINE)
    cef = parse_cef(CEF_LINE)
    assert cef.vendor == "Palo Alto"
    assert cef.name == "Malware Download Blocked"
    assert cef.severity == 9
    assert cef.extensions["src"] == "203.0.113.50"
    assert cef.extensions["dst"] == "10.0.0.8"
    assert cef.extensions["suser"] == "jdoe"


def test_cef_escaped_pipe_in_name():
    line = "CEF:0|Vendor|Prod|1.0|42|Name with \\| pipe|5|src=1.2.3.4"
    cef = parse_cef(line)
    assert cef.name == "Name with | pipe"


def test_non_cef_returns_none():
    assert parse_cef("plain message") is None


# ── mapper ────────────────────────────────────────────────────────────────────

def test_map_rfc3164_to_raw_alert():
    alert = map_syslog_to_raw_alert(RFC3164, peer_host="192.168.1.50")
    assert alert.group == "SYSLOG"
    assert alert.type == "syslog_event"
    assert alert.source == "syslog:web01"
    assert alert.raw_severity == 3  # syslog critical -> 3
    assert alert.entity_ids.ip == ["203.0.113.9"]
    assert alert.entity_ids.user == ["root"]
    assert alert.ground_truth_label == "UNLABELED"


def test_map_cef_to_raw_alert():
    alert = map_syslog_to_raw_alert(CEF_LINE)
    assert alert.type == "cef_event"
    assert alert.raw_severity == 3  # CEF 9 -> 3
    assert alert.entity_ids.ip == ["203.0.113.50"]
    assert "203.0.113.50" in alert.entity_ids.ips and "10.0.0.8" in alert.entity_ids.ips
    assert alert.entity_ids.user == ["jdoe"]
    assert "Malware Download Blocked" in alert.message


def test_mapped_alert_flows_through_pipeline(db):
    from app.models.db_models import ScoredAlertDB
    from app.services.pipeline import process_raw_alert

    alert = map_syslog_to_raw_alert(RFC3164, peer_host="192.168.1.50")
    scored, _ = process_raw_alert(db, alert)
    assert db.query(ScoredAlertDB).filter_by(raw_alert_id=alert.id).one()
    assert scored.risk_score > 0
