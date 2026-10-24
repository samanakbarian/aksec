import io
from pathlib import Path

from aksec.adapters.nmap import parse_nmap_xml
from aksec.export import export
from aksec.storage import Store

NMAP_XML = Path(__file__).resolve().parents[1] / "examples" / "nmap-sample.xml"


def test_nmap_parses_only_open_ports():
    obs = list(parse_nmap_xml(NMAP_XML.read_text()))
    pairs = {(o.ip, o.port) for o in obs}
    assert ("198.51.100.77", 22) in pairs
    assert ("198.51.100.77", 443) in pairs
    assert ("198.51.100.88", 3389) in pairs
    # closed port 25 must be excluded
    assert ("198.51.100.77", 25) not in pairs


def test_nmap_builds_banner_and_detail():
    obs = {(o.ip, o.port): o for o in parse_nmap_xml(NMAP_XML.read_text())}
    ssh = obs[("198.51.100.77", 22)]
    assert ssh.service == "ssh"
    assert "OpenSSH" in (ssh.banner or "")
    assert ssh.data["nmap_service"]["product"] == "OpenSSH"


def test_nmap_timestamp_from_start_attr():
    obs = list(parse_nmap_xml(NMAP_XML.read_text()))
    assert obs[0].observed_at.year == 2023  # start=1700000000 -> 2023


def test_export_ndjson_roundtrip(store, tmp_path):
    buf = io.StringIO()
    n = export(store, buf, "ndjson")
    assert n == store.count()
    # re-import into a fresh store yields the same count
    s2 = Store(tmp_path / "rt.db")
    from aksec.ingest import ingest_stream

    report = ingest_stream(s2, io.StringIO(buf.getvalue()))
    assert report.imported == n
    assert s2.count() == store.count()
    s2.close()


def test_export_csv_has_header(store):
    buf = io.StringIO()
    export(store, buf, "csv")
    lines = buf.getvalue().splitlines()
    assert lines[0].startswith("ip,port,transport")
    assert len(lines) == store.count() + 1
