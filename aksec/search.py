"""High-level search: parse a query string, run it, group by host."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .query import compile_query
from .storage import Store


@dataclass
class SearchResult:
    total: int
    limit: int
    offset: int
    services: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "services": self.services,
        }


def search(store: Store, query: str, limit: int = 50, offset: int = 0) -> SearchResult:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    compiled = compile_query(query)
    total, rows = store.run_query(compiled.where, compiled.params, limit, offset)
    return SearchResult(total=total, limit=limit, offset=offset, services=rows)
