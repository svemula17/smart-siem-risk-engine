import httpx

from app.models.db_models import IOCDB, ThreatFeedStateDB
from app.services import threat_feeds


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_feeds_noop_without_keys(db):
    assert threat_feeds.sync_abuseipdb(db) == 0
    assert threat_feeds.sync_otx(db) == 0
    states = {s.feed: s for s in db.query(ThreatFeedStateDB).all()}
    assert "disabled" in states["abuseipdb"].last_status
    assert "disabled" in states["otx"].last_status


def test_abuseipdb_sync_writes_iocs(db, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _FakeResponse({
        "data": [
            {"ipAddress": "203.0.113.201", "abuseConfidenceScore": 100},
            {"ipAddress": "203.0.113.202", "abuseConfidenceScore": 80},
        ]
    }))

    assert threat_feeds.sync_abuseipdb(db) == 2
    iocs = {i.value: i for i in db.query(IOCDB).all()}
    assert iocs["203.0.113.201"].severity == "Critical"
    assert iocs["203.0.113.202"].severity == "Medium"
    assert iocs["203.0.113.201"].source == "AbuseIPDB"
    assert iocs["203.0.113.201"].expires_at is not None

    state = db.query(ThreatFeedStateDB).filter_by(feed="abuseipdb").one()
    assert state.last_status == "ok" and state.items_synced == 2


def test_otx_sync_maps_indicator_types(db, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "OTX_API_KEY", "test-key")
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _FakeResponse({
        "results": [{
            "name": "Emotet Campaign",
            "tags": ["emotet"],
            "indicators": [
                {"type": "IPv4", "indicator": "198.51.100.66"},
                {"type": "domain", "indicator": "bad.example.net"},
                {"type": "FileHash-SHA256", "indicator": "a" * 64},
                {"type": "YARA", "indicator": "ignored-unsupported"},
            ],
        }]
    }))

    assert threat_feeds.sync_otx(db) == 3
    types = {i.value: i.ioc_type for i in db.query(IOCDB).all()}
    assert types["198.51.100.66"] == "ip"
    assert types["bad.example.net"] == "domain"
    assert types["a" * 64] == "hash"


def test_feed_error_recorded_not_raised(db, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "test-key")

    def boom(*a, **kw):
        raise httpx.ConnectError("network down")
    monkeypatch.setattr(httpx, "get", boom)

    assert threat_feeds.sync_abuseipdb(db) == 0
    state = db.query(ThreatFeedStateDB).filter_by(feed="abuseipdb").one()
    assert state.last_status.startswith("error:")


def test_expire_stale_iocs(db):
    from app.services.ioc_manager import add_ioc
    add_ioc(db, "ip", "192.0.2.1", expires_at="2000-01-01T00:00:00")
    add_ioc(db, "ip", "192.0.2.2", expires_at="2999-01-01T00:00:00")
    add_ioc(db, "ip", "192.0.2.3")  # no expiry

    assert threat_feeds.expire_stale_iocs(db) == 1
    active = {i.value for i in db.query(IOCDB).filter(IOCDB.is_active == True).all()}
    assert active == {"192.0.2.2", "192.0.2.3"}


def test_ioc_backed_threat_intel_lookup(db, monkeypatch):
    """get_intel_for_ip prefers live IOC data over the mock."""
    import app.services.threat_intel as ti_mod
    from app.services.ioc_manager import add_ioc

    add_ioc(db, "ip", "203.0.113.77", severity="Critical", source="OTX", tags=["c2"])

    # Point the service's session factory at the test DB
    monkeypatch.setattr(
        "app.database.SessionLocal", lambda: db
    )
    monkeypatch.setattr(db, "close", lambda: None)  # service closes the session

    intel = ti_mod.ThreatIntelService(cache_file=":memory:").get_intel_for_ip("203.0.113.77")
    assert intel["provider"] == "OTX"
    assert intel["score"] == 95
    assert intel["tags"] == ["c2"]
