"""Target expansion: CIDRs minus exclusions, iterated in a pseudo-random order.

Visiting (ip, port) pairs in a scattered order spreads load across networks
instead of hammering one subnet at a time, the same idea ZMap uses.
"""

from __future__ import annotations

import bisect
import ipaddress
import math
import random
from collections.abc import Iterable, Iterator
from pathlib import Path

RESERVED_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
]


def load_blocklist(path: Path | None) -> list[ipaddress.IPv4Network]:
    if path is None or not path.exists():
        return []
    nets = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.IPv4Network(line, strict=False))
    return nets


class Exclusions:
    """Fast membership test for a set of IPv4 networks using sorted intervals."""

    def __init__(self, networks: Iterable[ipaddress.IPv4Network]):
        collapsed = ipaddress.collapse_addresses(networks)
        self._starts: list[int] = []
        self._ends: list[int] = []
        for net in collapsed:
            self._starts.append(int(net.network_address))
            self._ends.append(int(net.broadcast_address))

    def __contains__(self, ip: int) -> bool:
        i = bisect.bisect_right(self._starts, ip) - 1
        return i >= 0 and ip <= self._ends[i]


class TargetSpace:
    """All (ip, port) pairs to probe, with exclusions applied lazily during iteration."""

    def __init__(
        self,
        cidrs: Iterable[str],
        ports: Iterable[int],
        exclude: Iterable[ipaddress.IPv4Network] = (),
        allow_reserved: bool = False,
    ):
        self.networks = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(c, strict=False) for c in cidrs))
        self.ports = sorted(set(ports))
        if not self.networks or not self.ports:
            raise ValueError("at least one target network and one port are required")
        excluded = list(exclude)
        if not allow_reserved:
            excluded += [ipaddress.IPv4Network(n) for n in RESERVED_V4]
        self.exclusions = Exclusions(excluded)
        self._offsets: list[int] = []
        total = 0
        for net in self.networks:
            self._offsets.append(total)
            total += net.num_addresses
        self.num_ips = total

    def __len__(self) -> int:
        return self.num_ips * len(self.ports)

    def _ip_at(self, index: int) -> int:
        i = bisect.bisect_right(self._offsets, index) - 1
        return int(self.networks[i].network_address) + index - self._offsets[i]

    def __iter__(self) -> Iterator[tuple[str, int]]:
        return self.iterate()

    def iterate(self, seed: int | None = None) -> Iterator[tuple[str, int]]:
        n = len(self)
        rng = random.Random(seed)
        # Affine permutation x -> (a*x + c) mod n visits every index exactly once.
        a = rng.randrange(1, n) if n > 1 else 1
        while math.gcd(a, n) != 1:
            a = rng.randrange(1, n)
        c = rng.randrange(n)
        nports = len(self.ports)
        for x in range(n):
            idx = (a * x + c) % n
            ip = self._ip_at(idx // nports)
            if ip in self.exclusions:
                continue
            yield str(ipaddress.IPv4Address(ip)), self.ports[idx % nports]


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,8000-8010' into a sorted list of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(p) for p in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError(f"invalid port specification: {spec!r}")
    return sorted(ports)
