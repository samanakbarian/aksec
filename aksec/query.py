"""A small, safe search query language compiled to parameterised SQL.

Grammar (whitespace-separated terms, implicitly AND-ed)::

    port:443            exact port
    port:8000-8100      port range
    service:https       exact service name
    ip:10.0.0.0/8       host or CIDR membership
    source:acme-import  exact source
    banner:nginx        substring match in the banner
    has:tls             a protocol block is present in `data`
    nginx               free text -> full-text search over banner + data

Every value becomes a bound parameter, so query strings can never inject SQL.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from datetime import date, datetime
from dataclasses import dataclass


class QueryError(ValueError):
    """Raised when a query string cannot be parsed."""


@dataclass
class CompiledQuery:
    where: str
    params: list[object]


_TERM = re.compile(r"^(?P<field>[a-z_]+):(?P<value>.+)$")
# FTS rowids are collected in a subquery; keeps the main WHERE clause simple.
_FTS_SUBQUERY = "rowid IN (SELECT rowid FROM service_fts WHERE service_fts MATCH ?)"


def compile_query(text: str) -> CompiledQuery:
    text = (text or "").strip()
    if not text:
        return CompiledQuery(where="1=1", params=[])

    clauses: list[str] = []
    params: list[object] = []
    free_terms: list[str] = []

    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise QueryError(f"could not parse query: {exc}") from exc

    for token in tokens:
        m = _TERM.match(token)
        if not m:
            free_terms.append(token)
            continue
        field, value = m.group("field"), m.group("value")
        _compile_term(field, value, clauses, params)

    if free_terms:
        clauses.append(_FTS_SUBQUERY)
        params.append(" ".join(_fts_escape(t) for t in free_terms))

    if not clauses:
        return CompiledQuery(where="1=1", params=[])
    return CompiledQuery(where=" AND ".join(clauses), params=params)


def _compile_term(field: str, value: str, clauses: list[str], params: list[object]) -> None:
    if field == "port":
        if "-" in value:
            lo, hi = _parse_port_range(value)
            clauses.append("port BETWEEN ? AND ?")
            params += [lo, hi]
        else:
            clauses.append("port = ?")
            params.append(_parse_port(value))
    elif field in ("service", "source", "transport"):
        clauses.append(f"{field} = ?")
        params.append(value.lower() if field != "source" else value)
    elif field == "ip":
        _compile_ip(value, clauses, params)
    elif field == "banner":
        clauses.append("banner LIKE ?")
        params.append(f"%{_like_escape(value)}%")
        clauses[-1] += " ESCAPE '\\'"
    elif field == "has":
        clauses.append("json_extract(data, '$.' || ?) IS NOT NULL")
        params.append(value)
    elif field in ("seen_since", "seen_before"):
        iso = _parse_date(field, value)
        op = ">=" if field == "seen_since" else "<"
        clauses.append(f"last_seen {op} ?")
        params.append(iso)
    else:
        raise QueryError(f"unknown field: {field!r}")


def _compile_ip(value: str, clauses: list[str], params: list[object]) -> None:
    try:
        if "/" in value:
            # Validate here; membership is evaluated per-row by the ip_in_cidr
            # SQL function, which handles both IPv4 and IPv6.
            net = ipaddress.ip_network(value, strict=False)
            clauses.append("ip_in_cidr(ip, ?)")
            params.append(str(net))
        else:
            clauses.append("ip = ?")
            params.append(str(ipaddress.ip_address(value)))
    except ValueError as exc:
        raise QueryError(f"invalid ip/cidr: {value!r}") from exc


def _parse_port(value: str) -> int:
    try:
        p = int(value)
    except ValueError as exc:
        raise QueryError(f"invalid port: {value!r}") from exc
    if not 1 <= p <= 65535:
        raise QueryError(f"port out of range: {p}")
    return p


def _parse_port_range(value: str) -> tuple[int, int]:
    lo_s, hi_s = value.split("-", 1)
    lo, hi = _parse_port(lo_s), _parse_port(hi_s)
    if lo > hi:
        raise QueryError(f"port range reversed: {value!r}")
    return lo, hi


def _parse_date(field: str, value: str) -> str:
    """Accept YYYY-MM-DD or a full ISO-8601 timestamp; return a comparable ISO string."""
    try:
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise QueryError(f"invalid date for {field}: {value!r}") from exc


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _fts_escape(term: str) -> str:
    # Quote each term so FTS5 treats it as a literal, not an operator.
    return '"' + term.replace('"', '""') + '"'


def _ip_in_cidr(ip: str | None, network: str) -> int:
    if not ip:
        return 0
    try:
        return int(ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False))
    except ValueError:
        return 0


def register_functions(conn) -> None:
    """Register SQL helpers used by IP/CIDR queries (IPv4 and IPv6)."""
    conn.create_function("ip_in_cidr", 2, _ip_in_cidr, deterministic=True)
