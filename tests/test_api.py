import io

from fastapi.testclient import TestClient

from aksec.ingest import ingest_stream
from aksec.storage import Store
from aksec.web.api import create_app
from tests.conftest import SAMPLE


def make_client(tmp_path):
    db = tmp_path / "api.db"
    s = Store(db)
    ingest_stream(s, io.StringIO(SAMPLE))
    s.close()
    return TestClient(create_app(str(db)))


def test_search_endpoint(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/api/search", params={"q": "port:3306"})
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_bad_query_returns_400(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/api/search", params={"q": "nope:1"})
    assert r.status_code == 400


def test_host_endpoint_with_findings(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/api/host/198.51.100.23")
    assert r.status_code == 200
    body = r.json()
    assert any(f["code"] == "sensitive-port" for f in body["findings"])


def test_host_404(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/host/8.8.8.8").status_code == 404


def test_stats_endpoint(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/api/stats")
    assert r.json()["hosts"] == 3


def test_index_served(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/")
    assert r.status_code == 200
    assert "aksec" in r.text
