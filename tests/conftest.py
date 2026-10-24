import io

import pytest

from aksec.ingest import ingest_stream
from aksec.storage import Store

SAMPLE = """\
{"ip": "198.51.100.10", "port": 443, "service": "https", "source": "demo", "banner": "nginx/1.24.0", "data": {"tls": {"subject": "CN=www.example.com", "not_after": "2020-01-01T00:00:00Z", "version": "TLSv1.3"}}}
{"ip": "198.51.100.10", "port": 22, "service": "ssh", "source": "demo", "banner": "SSH-2.0-OpenSSH_9.6"}
{"ip": "198.51.100.23", "port": 3306, "service": "mysql", "source": "demo", "banner": "5.7.42-log"}
{"ip": "203.0.113.5", "port": 3389, "service": "rdp", "source": "demo", "banner": ""}
"""


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    ingest_stream(s, io.StringIO(SAMPLE))
    yield s
    s.close()
