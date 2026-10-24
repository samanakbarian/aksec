from aksec.analysis import analyze_service
from aksec.vulndb import match_version, parse_version


def test_parse_version():
    assert parse_version("nginx/1.24.0") == (1, 24, 0)
    assert parse_version("SSH-2.0-OpenSSH_9.6") == (2, 0)  # first dotted run
    assert parse_version("no version here") is None


def test_match_below_fixed():
    rules = match_version("nginx", "nginx/1.18.0")
    assert rules and rules[0].severity == "low"


def test_no_match_at_or_above_fixed():
    assert match_version("nginx", "nginx/1.20.0") == []
    assert match_version("nginx", "nginx/1.25.3") == []


def test_ssh_alias():
    assert match_version("ssh", "OpenSSH 8.1") != []
    assert match_version("ssh", "OpenSSH 9.6") == []


def test_version_finding_from_nmap_detail():
    row = {
        "ip": "1.1.1.1", "port": 443, "service": "http", "banner": "nginx 1.18.0",
        "data": {"nmap_service": {"product": "nginx", "version": "1.18.0"}},
    }
    findings = analyze_service(row)
    vuln = [f for f in findings if f.code == "known-vuln"]
    assert len(vuln) == 1  # deduped across candidates
    assert "nginx" in vuln[0].message
