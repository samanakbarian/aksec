"""Export the inventory back out as NDJSON or CSV."""

from __future__ import annotations

import csv
import json
from typing import Any, Iterable, TextIO

from .storage import Store

_CSV_FIELDS = ["ip", "port", "transport", "service", "banner", "observed_at", "first_seen", "last_seen", "source"]


def export_ndjson(store: Store, out: TextIO) -> int:
    n = 0
    for row in store.iter_all():
        out.write(json.dumps(row, default=str, sort_keys=True) + "\n")
        n += 1
    return n


def export_csv(store: Store, out: TextIO) -> int:
    writer = csv.DictWriter(out, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    n = 0
    for row in store.iter_all():
        writer.writerow({k: row.get(k, "") for k in _CSV_FIELDS})
        n += 1
    return n


def export(store: Store, out: TextIO, fmt: str = "ndjson") -> int:
    if fmt == "ndjson":
        return export_ndjson(store, out)
    if fmt == "csv":
        return export_csv(store, out)
    raise ValueError(f"unknown export format: {fmt!r}")
