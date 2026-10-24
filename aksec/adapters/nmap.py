"""Convert nmap XML output (``nmap -oX file.xml ...``) into Observations.

This is a pure file transformer: it parses XML that nmap has already written
and emits `Observation` records. It performs no network activity of its own.

Usage::

    from aksec.adapters.nmap import parse_nmap_xml
    for obs in parse_nmap_xml(open("scan.xml")):
        ...
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any, TextIO
from xml.etree import ElementTree as ET

from ..models import Observation


def parse_nmap_xml(source: TextIO | str, default_source: str = "nmap") -> Iterator[Observation]:
    """Yield an Observation for every open port in an nmap XML document."""
    tree = ET.parse(source) if hasattr(source, "read") else ET.ElementTree(ET.fromstring(source))
    root = tree.getroot()

    run_time = _run_timestamp(root)

    for host in root.findall("host"):
        ip = _host_ipv4(host)
        if ip is None:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            yield _build_observation(ip, port, run_time, default_source)


def _run_timestamp(root: ET.Element) -> datetime:
    start = root.get("start")
    if start and start.isdigit():
        return datetime.fromtimestamp(int(start), tz=timezone.utc)
    return datetime.now(timezone.utc)


def _host_ipv4(host: ET.Element) -> str | None:
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    return None


def _build_observation(ip: str, port: ET.Element, when: datetime, source: str) -> Observation:
    transport = port.get("protocol", "tcp")
    portid = int(port.get("portid", "0"))
    svc = port.find("service")

    service_name = "unknown"
    data: dict[str, Any] = {}
    banner: str | None = None

    if svc is not None:
        service_name = svc.get("name", "unknown")
        product = svc.get("product")
        version = svc.get("version")
        extrainfo = svc.get("extrainfo")
        banner = " ".join(p for p in (product, version, extrainfo) if p) or None
        detail = {k: svc.get(k) for k in ("product", "version", "extrainfo", "ostype", "method") if svc.get(k)}
        if detail:
            data["nmap_service"] = detail

    return Observation(
        ip=ip,
        port=portid,
        transport="udp" if transport == "udp" else "tcp",
        service=service_name,
        banner=banner,
        observed_at=when,
        source=source,
        data=data,
    )
