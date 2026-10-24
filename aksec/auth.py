"""API-key authentication and tenant resolution.

Multi-tenancy uses **isolation by database**: each tenant's data lives in its
own SQLite file under a data directory, so one tenant can never see another's
rows. An API key maps to a tenant.

Configuration (JSON), from the path in ``AKSEC_AUTH`` or passed explicitly::

    {
      "data_dir": "data",
      "keys": { "secret-key-1": "acme", "secret-key-2": "globex" }
    }

If no keys are configured the API runs in **open mode**: no key is required
and all requests use a single store (the ``db_path`` given to the app). This
keeps local, single-user use friction-free while allowing locked-down
multi-tenant deployments.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


@dataclass
class AuthConfig:
    # Map of API key -> tenant name. Empty means open mode.
    keys: dict[str, str] = field(default_factory=dict)
    data_dir: Path = field(default_factory=lambda: Path("data"))

    @property
    def enabled(self) -> bool:
        return bool(self.keys)

    def tenant_for(self, api_key: str | None) -> str | None:
        if not self.enabled:
            return None  # open mode
        if not api_key:
            return None
        return self.keys.get(api_key)

    def db_path_for(self, tenant: str) -> Path:
        if not _TENANT_RE.match(tenant):
            raise ValueError(f"invalid tenant name: {tenant!r}")
        return self.data_dir / f"{tenant}.db"


def load_auth(path: str | os.PathLike | None = None) -> AuthConfig:
    """Load auth config from a path, from ``AKSEC_AUTH``, or return open mode."""
    path = path or os.environ.get("AKSEC_AUTH")
    if not path:
        return AuthConfig()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    keys = {str(k): str(v) for k, v in (data.get("keys") or {}).items()}
    for tenant in keys.values():
        if not _TENANT_RE.match(tenant):
            raise ValueError(f"invalid tenant name in auth config: {tenant!r}")
    data_dir = Path(data.get("data_dir", "data"))
    return AuthConfig(keys=keys, data_dir=data_dir)
