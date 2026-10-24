"""Observation schema: the contract between data collection and the rest of the platform.

Any collector (our own scanner, a third-party tool, a partner feed) delivers
newline-delimited JSON where each line is one `Observation`. See
docs/DATA_SCHEMA.md for the full description.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Observation(BaseModel):
    ip: str
    port: int = Field(ge=1, le=65535)
    transport: Literal["tcp", "udp"] = "tcp"
    service: str = "unknown"
    banner: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    # Protocol-specific details, e.g. {"http": {...}, "tls": {...}, "ssh": {...}}.
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip")
    @classmethod
    def _valid_ipv4(cls, v: str) -> str:
        return str(ipaddress.IPv4Address(v.strip()))

    @field_validator("service")
    @classmethod
    def _normalize_service(cls, v: str) -> str:
        return v.strip().lower() or "unknown"

    @field_validator("observed_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
