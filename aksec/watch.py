"""Saved searches and simple alerting.

A saved search is a named query. Running it compares the services matching
*now* against the baseline captured at the previous run and reports what has
newly appeared (and, optionally, what has disappeared). Running updates the
baseline, so each run reports changes since the last one — enough to answer
"tell me when a new 3389 shows up" without any always-on infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .query import compile_query
from .storage import Store


@dataclass
class WatchResult:
    name: str
    query: str
    total: int
    appeared: list[dict[str, Any]] = field(default_factory=list)
    disappeared: list[str] = field(default_factory=list)
    first_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "query": self.query,
            "total": self.total,
            "first_run": self.first_run,
            "appeared": self.appeared,
            "disappeared": self.disappeared,
        }


def add_watch(store: Store, name: str, query: str) -> None:
    compile_query(query)  # validate up front
    store.save_search(name, query)


def list_watches(store: Store) -> list[dict[str, Any]]:
    out = []
    for s in store.list_searches():
        out.append(
            {
                "name": s["name"],
                "query": s["query"],
                "last_run": s["last_run"],
                "tracked": len(s["baseline"]),
            }
        )
    return out


def run_watch(store: Store, name: str) -> WatchResult:
    search = store.get_search(name)
    if search is None:
        raise KeyError(name)

    compiled = compile_query(search["query"])
    current = store.query_keys(compiled.where, compiled.params)
    baseline = search["baseline"]
    first_run = search["last_run"] is None

    appeared_keys = sorted(current - baseline)
    disappeared = sorted(baseline - current)

    # On the very first run everything is "new"; don't flood the report.
    appeared_rows: list[dict[str, Any]] = []
    if not first_run:
        appeared_rows = [r for k in appeared_keys if (r := store.get_service(k))]

    store.update_search_baseline(name, current)

    return WatchResult(
        name=name,
        query=search["query"],
        total=len(current),
        appeared=appeared_rows,
        disappeared=disappeared if not first_run else [],
        first_run=first_run,
    )
