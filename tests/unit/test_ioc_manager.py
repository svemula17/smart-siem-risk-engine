from app.models.db_models import IOCDB
from app.services import ioc_manager


def test_add_and_fetch_ioc(db):
    ioc = ioc_manager.add_ioc(db, "ip", "198.51.100.7", severity="Critical", source="Test", tags=["c2"])
    assert ioc.id is not None
    all_iocs = ioc_manager.get_all_iocs(db)
    assert len(all_iocs) == 1
    assert all_iocs[0]["tags"] == ["c2"]


def test_add_dedupes_on_value_and_type(db):
    ioc_manager.add_ioc(db, "ip", "198.51.100.7", severity="High")
    ioc_manager.add_ioc(db, "ip", "198.51.100.7", severity="Critical")
    assert db.query(IOCDB).count() == 1
    assert db.query(IOCDB).one().severity == "Critical"


def test_delete_deactivates(db):
    ioc = ioc_manager.add_ioc(db, "domain", "evil.example.com")
    assert ioc_manager.delete_ioc(db, ioc.id)
    assert ioc_manager.get_all_iocs(db) == []
    assert ioc_manager.get_all_iocs(db, active_only=False) != []


def test_ip_match(db):
    ioc_manager.add_ioc(db, "ip", "203.0.113.99")
    assert ioc_manager.check_ip_against_ioc(db, "203.0.113.99") is not None
    assert ioc_manager.check_ip_against_ioc(db, "10.1.1.1") is None
    assert ioc_manager.check_ip_against_ioc(db, None) is None


def test_stats(db):
    ioc_manager.add_ioc(db, "ip", "1.2.3.4", severity="High")
    ioc_manager.add_ioc(db, "hash", "abcd", severity="High")
    stats = ioc_manager.get_ioc_stats(db)
    assert stats["total"] == 2
    assert stats["by_type"] == {"ip": 1, "hash": 1}
