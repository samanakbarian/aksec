"""A tiny, curated set of version-based advisories.

This is intentionally *not* a full vulnerability feed. It is a small, static
table of "service X below version Y is known-bad" rules, used to turn version
strings already present in the inventory into advisory findings. Extend it or
replace it with a real feed (NVD, OSV) behind the same `match_version()`
interface — see docs/ROADMAP.md.

Each rule says: for this service name, any version strictly below `fixed`
should be flagged, with a human-readable note.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnRule:
    service: str
    fixed: tuple[int, ...]
    severity: str
    note: str


# Illustrative rules only. Versions are "flag if strictly below fixed".
RULES: list[VulnRule] = [
    VulnRule("openssh", (8, 5), "medium", "OpenSSH < 8.5 misses several hardening fixes; upgrade"),
    VulnRule("nginx", (1, 20), "low", "nginx < 1.20 is end-of-life for the stable branch; upgrade"),
    VulnRule("apache", (2, 4, 52), "medium", "Apache httpd < 2.4.52 has multiple known CVEs; upgrade"),
    VulnRule("openssl", (3, 0, 7), "high", "OpenSSL < 3.0.7 is affected by high-severity CVEs; upgrade"),
    VulnRule("exim", (4, 95), "high", "Exim < 4.95 has remote-code-execution CVEs; upgrade"),
    VulnRule("vsftpd", (3, 0, 3), "medium", "vsftpd < 3.0.3 has known issues; upgrade"),
]

_RULES_BY_SERVICE: dict[str, list[VulnRule]] = {}
for _r in RULES:
    _RULES_BY_SERVICE.setdefault(_r.service, []).append(_r)

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Extract a dotted numeric version from arbitrary banner/version text."""
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    # Compare component-wise, treating missing trailing components as 0.
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a < b


def match_version(service: str, version_text: str | None) -> list[VulnRule]:
    """Return rules that apply to this service at the given version."""
    service = (service or "").lower()
    product = _normalize_product(service)
    rules = _RULES_BY_SERVICE.get(product, [])
    if not rules:
        return []
    version = parse_version(version_text)
    if version is None:
        return []
    return [r for r in rules if _lt(version, r.fixed)]


def _normalize_product(name: str) -> str:
    # Map a few common aliases to the rule keys above.
    aliases = {
        "ssh": "openssh",
        "http": "",  # ambiguous; rely on explicit product strings instead
        "https": "",
        "httpd": "apache",
        "apache httpd": "apache",
    }
    return aliases.get(name, name)
