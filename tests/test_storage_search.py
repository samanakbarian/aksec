from aksec.search import search


def test_counts(store):
    assert store.host_count() == 3
    assert store.count() == 4


def test_search_by_port(store):
    r = search(store, "port:3306")
    assert r.total == 1
    assert r.services[0]["service"] == "mysql"


def test_search_by_cidr(store):
    r = search(store, "ip:198.51.100.0/24")
    assert r.total == 3  # two services on .10, one on .23


def test_search_free_text(store):
    r = search(store, "openssh")
    assert r.total == 1
    assert r.services[0]["port"] == 22


def test_get_host(store):
    host = store.get_host("198.51.100.10")
    assert host is not None
    assert {s["port"] for s in host["services"]} == {443, 22}


def test_upsert_in_place(store):
    before = store.count()
    from aksec.models import Observation

    store.upsert(Observation(ip="198.51.100.10", port=22, service="ssh", banner="updated"))
    assert store.count() == before  # replaced, not added
    host = store.get_host("198.51.100.10")
    ssh = next(s for s in host["services"] if s["port"] == 22)
    assert ssh["banner"] == "updated"
