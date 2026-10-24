from datetime import datetime, timezone

from aksec.models import Observation
from aksec.search import search
from aksec.storage import Store


def test_first_and_last_seen_set_on_insert(store):
    host = store.get_host("198.51.100.10")
    svc = host["services"][0]
    assert svc["first_seen"] == svc["observed_at"]
    assert svc["last_seen"] == svc["observed_at"]


def test_history_tracks_min_and_max(tmp_path):
    s = Store(tmp_path / "h.db")
    t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    t2 = datetime(2025, 6, 1, tzinfo=timezone.utc)
    s.upsert(Observation(ip="10.0.0.1", port=80, service="http", observed_at=t2))
    s.upsert(Observation(ip="10.0.0.1", port=80, service="http", observed_at=t1))
    svc = s.get_host("10.0.0.1")["services"][0]
    assert svc["first_seen"].startswith("2025-01-01")
    assert svc["last_seen"].startswith("2025-06-01")
    s.close()


def test_migrates_pre_0_2_database(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript(
        """CREATE TABLE service (ip TEXT, port INTEGER, transport TEXT DEFAULT 'tcp',
           service TEXT, banner TEXT, observed_at TEXT, source TEXT, data TEXT DEFAULT '{}',
           PRIMARY KEY(ip,port,transport));"""
    )
    c.execute("INSERT INTO service VALUES ('10.0.0.1',80,'tcp','http','x','2025-05-05T00:00:00+00:00','old','{}')")
    c.commit()
    c.close()

    s = Store(path)  # triggers migration
    svc = s.get_host("10.0.0.1")["services"][0]
    assert svc["first_seen"] == "2025-05-05T00:00:00+00:00"
    assert svc["last_seen"] == "2025-05-05T00:00:00+00:00"
    s.close()


def test_seen_since_query(tmp_path):
    s = Store(tmp_path / "h2.db")
    old = datetime(2024, 1, 1, tzinfo=timezone.utc)
    new = datetime(2026, 1, 1, tzinfo=timezone.utc)
    s.upsert(Observation(ip="10.0.0.1", port=22, observed_at=old))
    s.upsert(Observation(ip="10.0.0.2", port=22, observed_at=new))
    r = search(s, "seen_since:2025-06-01")
    assert r.total == 1
    assert r.services[0]["ip"] == "10.0.0.2"
    s.close()
