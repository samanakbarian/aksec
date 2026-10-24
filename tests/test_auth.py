import io
import json

from fastapi.testclient import TestClient

from aksec.auth import AuthConfig, load_auth
from aksec.ingest import ingest_stream
from aksec.storage import Store
from aksec.web.api import create_app
from tests.conftest import SAMPLE


def test_open_mode_requires_no_key(tmp_path):
    db = tmp_path / "open.db"
    s = Store(db)
    ingest_stream(s, io.StringIO(SAMPLE))
    s.close()
    client = TestClient(create_app(str(db), auth=AuthConfig()))
    assert client.get("/api/stats").status_code == 200


def test_multitenant_rejects_without_key(tmp_path):
    auth = AuthConfig(keys={"k-acme": "acme"}, data_dir=tmp_path / "data")
    client = TestClient(create_app(str(tmp_path / "ignored.db"), auth=auth))
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "wrong"}).status_code == 401


def test_multitenant_isolation(tmp_path):
    auth = AuthConfig(keys={"k-acme": "acme", "k-globex": "globex"}, data_dir=tmp_path / "data")
    app = create_app(str(tmp_path / "ignored.db"), auth=auth)
    client = TestClient(app)

    # Populate each tenant's isolated database via its own key path.
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    acme = Store(tmp_path / "data" / "acme.db")
    acme.close()  # create file; registry opens its own handle
    # Use the registry the app built so writes land where reads look.
    reg = app.state.registry
    reg.for_tenant("acme").bulk_upsert(list(_obs([("10.0.0.1", 80)])))
    reg.for_tenant("globex").bulk_upsert(list(_obs([("10.0.0.2", 443), ("10.0.0.3", 22)])))

    r_acme = client.get("/api/stats", headers={"X-API-Key": "k-acme"}).json()
    r_globex = client.get("/api/stats", headers={"X-API-Key": "k-globex"}).json()
    assert r_acme["services"] == 1
    assert r_globex["services"] == 2

    # acme must not see globex's host
    assert client.get("/api/host/10.0.0.2", headers={"X-API-Key": "k-acme"}).status_code == 404
    assert client.get("/api/host/10.0.0.2", headers={"X-API-Key": "k-globex"}).status_code == 200


def test_load_auth_from_file(tmp_path):
    cfg = tmp_path / "auth.json"
    cfg.write_text(json.dumps({"data_dir": str(tmp_path / "d"), "keys": {"key1": "tenant1"}}))
    auth = load_auth(cfg)
    assert auth.enabled
    assert auth.tenant_for("key1") == "tenant1"
    assert auth.tenant_for("nope") is None


def test_load_auth_open_mode_when_unset():
    assert load_auth(None).enabled is False


def _obs(pairs):
    from aksec.models import Observation

    for ip, port in pairs:
        yield Observation(ip=ip, port=port, service="x")
