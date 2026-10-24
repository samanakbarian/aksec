"""Heuristics that flag potentially risky exposure in your inventory.

These are *defensive* checks: given services you already know about, they
point out things worth reviewing — plaintext admin protocols reachable,
databases that should usually sit behind a firewall, expired or
soon-to-expire TLS certificates, and so on. Each finding is advisory; the
operator decides what is actually acceptable for their environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high"]

# Services that are risky to expose directly to an untrusted network.
_SENSITIVE_PORTS: dict[int, tuple[Severity, str]] = {
    23: ("high", "Telnet is unencrypted; credentials travel in cleartext"),
    21: ("medium", "FTP is typically unencrypted; prefer SFTP/FTPS"),
    3389: ("high", "RDP exposed; a frequent target for brute force and exploits"),
    445: ("high", "SMB exposed; should not be reachable from untrusted networks"),
    3306: ("high", "MySQL/MariaDB should normally sit behind a firewall"),
    5432: ("high", "PostgreSQL should normally sit behind a firewall"),
    6379: ("high", "Redis is often unauthenticated; do not expose it directly"),
    27017: ("high", "MongoDB should not be directly exposed"),
    9200: ("high", "Elasticsearch should not be directly exposed"),
}


@dataclass
class Finding:
    ip: str
    port: int
    severity: Severity
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def analyze_service(row: dict[str, Any]) -> list[Finding]:
    ip, port = row["ip"], row["port"]
    data = row.get("data") or {}
    findings: list[Finding] = []

    if port in _SENSITIVE_PORTS:
        sev, msg = _SENSITIVE_PORTS[port]
        findings.append(Finding(ip, port, sev, "sensitive-port", msg))

    tls = data.get("tls")
    if isinstance(tls, dict):
        findings += _analyze_tls(ip, port, tls)

    http = data.get("http")
    if isinstance(http, dict):
        findings += _analyze_http(ip, port, http)

    return findings


def _analyze_tls(ip: str, port: int, tls: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    not_after = tls.get("not_after")
    if isinstance(not_after, str):
        try:
            exp = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                out.append(Finding(ip, port, "high", "tls-expired", f"TLS certificate expired {-days} day(s) ago"))
            elif days < 30:
                out.append(Finding(ip, port, "medium", "tls-expiring", f"TLS certificate expires in {days} day(s)"))
        except ValueError:
            pass
    if tls.get("self_signed"):
        out.append(Finding(ip, port, "low", "tls-self-signed", "TLS certificate is self-signed"))
    version = tls.get("version")
    if isinstance(version, str) and version.upper() in ("SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"):
        out.append(Finding(ip, port, "high", "tls-weak-version", f"Obsolete TLS/SSL version: {version}"))
    return out


def _analyze_http(ip: str, port: int, http: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    headers = {k.lower(): v for k, v in (http.get("headers") or {}).items()}
    if port in (80, 8080) and "tls" not in http and http.get("status_code"):
        out.append(Finding(ip, port, "low", "http-plaintext", "Serving HTTP without TLS"))
    if "server" in headers:
        out.append(Finding(ip, port, "info", "server-banner", f"Server header reveals: {headers['server']}"))
    return out


def analyze_rows(rows: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        findings += analyze_service(row)
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.ip, f.port))
    return findings
