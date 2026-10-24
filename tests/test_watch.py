from aksec.models import Observation
from aksec.watch import add_watch, list_watches, run_watch


def test_first_run_captures_baseline(store):
    add_watch(store, "rdp", "port:3389")
    r = run_watch(store, "rdp")
    assert r.first_run is True
    assert r.total == 1
    assert r.appeared == []  # first run does not flood


def test_detects_newly_appeared(store):
    add_watch(store, "rdp", "port:3389")
    run_watch(store, "rdp")  # baseline
    store.upsert(Observation(ip="203.0.113.9", port=3389, service="rdp"))
    r = run_watch(store, "rdp")
    assert r.first_run is False
    assert len(r.appeared) == 1
    assert r.appeared[0]["ip"] == "203.0.113.9"


def test_detects_disappeared(store):
    add_watch(store, "mysql", "port:3306")
    run_watch(store, "mysql")
    # simulate the service going away by deleting the row directly
    store._conn.execute("DELETE FROM service WHERE port=3306")  # noqa: SLF001
    store._conn.commit()
    r = run_watch(store, "mysql")
    assert len(r.disappeared) == 1


def test_list_and_validation(store):
    add_watch(store, "web", "port:443")
    names = {w["name"] for w in list_watches(store)}
    assert "web" in names


def test_rejects_bad_query(store):
    import pytest

    from aksec.query import QueryError

    with pytest.raises(QueryError):
        add_watch(store, "bad", "nope:1")
