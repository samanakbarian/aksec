"""Load observations into the store from newline-delimited JSON (NDJSON).

Each line is one `Observation` (see docs/DATA_SCHEMA.md). Lines that fail to
parse are collected and reported rather than aborting the whole import, so a
single malformed record from a feed does not lose the rest.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .models import Observation
from .storage import Store


@dataclass
class IngestReport:
    imported: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        msg = f"imported {self.imported}, skipped {self.skipped}"
        if self.errors:
            msg += f" ({len(self.errors)} error(s))"
        return msg


def parse_ndjson(stream: Iterable[str]) -> Iterator[tuple[int, Observation | None, str | None]]:
    """Yield (line_number, observation, error) for each non-blank line."""
    for lineno, raw in enumerate(stream, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
            yield lineno, Observation.model_validate(obj), None
        except Exception as exc:  # noqa: BLE001 - report, don't crash the import
            yield lineno, None, str(exc)


def ingest_stream(store: Store, stream: TextIO) -> IngestReport:
    report = IngestReport()
    batch: list[Observation] = []
    for lineno, obs, err in parse_ndjson(stream):
        if err is not None:
            report.skipped += 1
            report.errors.append(f"line {lineno}: {err}")
            continue
        batch.append(obs)  # type: ignore[arg-type]
    report.imported = store.bulk_upsert(batch)
    return report


def ingest_file(store: Store, path: str | Path) -> IngestReport:
    with open(path, "r", encoding="utf-8") as fh:
        return ingest_stream(store, fh)
