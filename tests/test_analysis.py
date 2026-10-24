from aksec.analysis import analyze_rows, analyze_service


def test_sensitive_ports_flagged(store):
    rows = list(store.iter_all())
    findings = analyze_rows(rows)
    codes = {(f.port, f.code) for f in findings}
    assert (3306, "sensitive-port") in codes
    assert (3389, "sensitive-port") in codes


def test_expired_tls():
    row = {"ip": "1.1.1.1", "port": 443, "data": {"tls": {"not_after": "2020-01-01T00:00:00Z"}}}
    findings = analyze_service(row)
    assert any(f.code == "tls-expired" for f in findings)


def test_weak_tls_version():
    row = {"ip": "1.1.1.1", "port": 443, "data": {"tls": {"version": "TLSv1.0"}}}
    findings = analyze_service(row)
    assert any(f.code == "tls-weak-version" and f.severity == "high" for f in findings)


def test_missing_hsts_on_tls_site():
    row = {"ip": "1.1.1.1", "port": 443, "data": {"http": {"status_code": 200, "headers": {}}}}
    findings = analyze_service(row)
    assert any(f.code == "missing-hsts" for f in findings)


def test_directory_listing_detected():
    row = {"ip": "1.1.1.1", "port": 80, "data": {"http": {"status_code": 200, "title": "Index of /files"}}}
    findings = analyze_service(row)
    assert any(f.code == "directory-listing" and f.severity == "medium" for f in findings)


def test_ssh_protocol_1_flagged():
    row = {"ip": "1.1.1.1", "port": 22, "data": {"ssh": {"banner": "SSH-1.99-OpenSSH"}}}
    findings = analyze_service(row)
    assert any(f.code == "ssh-protocol-1" for f in findings)


def test_findings_sorted_by_severity(store):
    findings = analyze_rows(list(store.iter_all()))
    severities = [f.severity for f in findings]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    assert severities == sorted(severities, key=lambda s: order[s])
