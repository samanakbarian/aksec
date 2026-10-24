"""Runtime configuration, read from environment variables with safe defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.environ.get("AKSEC_DB", "aksec.db")))
    blocklist_path: Path | None = field(
        default_factory=lambda: Path(p) if (p := os.environ.get("AKSEC_BLOCKLIST", "config/blocklist.txt")) else None
    )
    # Probes per second across all workers. Keep this low unless you own the target network.
    rate: float = field(default_factory=lambda: _env_float("AKSEC_RATE", 100.0))
    concurrency: int = field(default_factory=lambda: _env_int("AKSEC_CONCURRENCY", 200))
    connect_timeout: float = field(default_factory=lambda: _env_float("AKSEC_CONNECT_TIMEOUT", 2.0))
    read_timeout: float = field(default_factory=lambda: _env_float("AKSEC_READ_TIMEOUT", 4.0))
    max_read_bytes: int = field(default_factory=lambda: _env_int("AKSEC_MAX_READ_BYTES", 65536))
    # Shown in the HTTP User-Agent so network operators can find out who we are and opt out.
    contact_url: str = field(default_factory=lambda: os.environ.get("AKSEC_CONTACT_URL", "https://example.org/aksec-scanning"))
    # Private, loopback and other reserved ranges are refused unless explicitly allowed (e.g. lab use).
    allow_reserved: bool = field(default_factory=lambda: os.environ.get("AKSEC_ALLOW_RESERVED", "0") == "1")

    @property
    def user_agent(self) -> str:
        return f"Mozilla/5.0 (compatible; aksec-scanner/0.1; +{self.contact_url})"
