"""SQLite-backed store for hosts and the services observed on them.

This is the system of record for an *attack-surface inventory*: you load
observations about assets you own or are authorised to assess, and query
them. Writing an observation upserts the service row keyed on
(ip, port, transport) so re-importing fresh data updates in place.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

from .models import Observation
from .query import register_functions

SCHEMA = """
CREATE TABLE IF NOT EXISTS service (
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    transport   TEXT    NOT NULL DEFAULT 'tcp',
    service     TEXT    NOT NULL DEFAULT 'unknown',
    banner      TEXT,
    observed_at TEXT    NOT NULL,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'unknown',
    data        TEXT    NOT NULL DEFAULT '{}',
    PRIMARY KEY (ip, port, transport)
);
CREATE INDEX IF NOT EXISTS idx_service_port    ON service(port);
CREATE INDEX IF NOT EXISTS idx_service_name    ON service(service);
CREATE INDEX IF NOT EXISTS idx_service_ip      ON service(ip);

-- Standalone FTS index (not external-content) so we manage its rows
-- explicitly, keyed on the service rowid.
CREATE VIRTUAL TABLE IF NOT EXISTS service_fts USING fts5(
    ip UNINDEXED, banner, data
);
"""


class Store:
    def __init__(self, path: str | Path = "aksec.db"):
        self.path = str(path)
        # check_same_thread=False + a lock lets the FastAPI thread pool share
        # one connection; all access is serialised through self._lock.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        register_functions(self._conn)
        self._conn.executescript(SCHEMA)
        self._migrate()
        # Created after migration so the column exists on upgraded databases too.
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_service_seen ON service(last_seen)")
        self._conn.commit()

    def _migrate(self) -> None:
        """Add history columns to pre-0.2 databases and backfill them."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(service)")}
        for col in ("first_seen", "last_seen"):
            if col not in cols:
                # SQLite needs a constant default when adding a NOT NULL column,
                # so add it nullable and backfill from observed_at.
                self._conn.execute(f"ALTER TABLE service ADD COLUMN {col} TEXT")
                self._conn.execute(f"UPDATE service SET {col}=observed_at WHERE {col} IS NULL")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writes ---------------------------------------------------------------

    def upsert(self, obs: Observation) -> None:
        with self._lock:
            self._upsert_one(obs)
            self._conn.commit()

    def bulk_upsert(self, observations: Iterable[Observation]) -> int:
        count = 0
        with self._lock:
            for obs in observations:
                self._upsert_one(obs)
                count += 1
            self._conn.commit()
        return count

    def _upsert_one(self, obs: Observation) -> None:
        data_json = json.dumps(obs.data, sort_keys=True, default=str)
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT INTO service (ip, port, transport, service, banner,
                                     observed_at, first_seen, last_seen, source, data)
                VALUES (:ip, :port, :transport, :service, :banner,
                        :observed_at, :observed_at, :observed_at, :source, :data)
                ON CONFLICT(ip, port, transport) DO UPDATE SET
                    service=excluded.service, banner=excluded.banner,
                    observed_at=excluded.observed_at, source=excluded.source,
                    data=excluded.data,
                    first_seen=MIN(service.first_seen, excluded.observed_at),
                    last_seen=MAX(service.last_seen, excluded.observed_at)
                """,
                {
                    "ip": obs.ip,
                    "port": obs.port,
                    "transport": obs.transport,
                    "service": obs.service,
                    "banner": obs.banner,
                    "observed_at": obs.observed_at.isoformat(),
                    "source": obs.source,
                    "data": data_json,
                },
            )
            rowid = cur.execute(
                "SELECT rowid FROM service WHERE ip=? AND port=? AND transport=?",
                (obs.ip, obs.port, obs.transport),
            ).fetchone()[0]
            cur.execute("DELETE FROM service_fts WHERE rowid=?", (rowid,))
            cur.execute(
                "INSERT INTO service_fts (rowid, ip, banner, data) VALUES (?, ?, ?, ?)",
                (rowid, obs.ip, obs.banner or "", data_json),
            )

    # -- reads ----------------------------------------------------------------

    def get_host(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM service WHERE ip=? ORDER BY port", (ip,)
            ).fetchall()
        if not rows:
            return None
        return {"ip": ip, "services": [self._row_to_dict(r) for r in rows]}

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM service").fetchone()[0]

    def host_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(DISTINCT ip) FROM service").fetchone()[0]

    def port_breakdown(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT port, COUNT(*) AS n FROM service GROUP BY port ORDER BY n DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"port": r["port"], "count": r["n"]} for r in rows]

    def service_breakdown(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT service, COUNT(*) AS n FROM service GROUP BY service ORDER BY n DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"service": r["service"], "count": r["n"]} for r in rows]

    def run_query(self, where: str, params: list[Any], limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM service WHERE {where}", params
            ).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM service WHERE {where} ORDER BY ip, port LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return total, [self._row_to_dict(r) for r in rows]

    def iter_all(self) -> Iterator[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM service ORDER BY ip, port").fetchall()
        for r in rows:
            yield self._row_to_dict(r)

    @staticmethod
    def _row_to_dict(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["data"] = json.loads(d.get("data") or "{}")
        return d
