"""FastAPI application exposing search, host detail, stats and exposure findings.

Run with::

    uvicorn aksec.web.api:create_app --factory

or via the CLI: ``aksec serve``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from ..analysis import analyze_rows
from ..query import QueryError
from ..search import search
from ..storage import Store

_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


def create_app(db_path: str = "aksec.db") -> FastAPI:
    app = FastAPI(title="aksec", description="Attack-surface inventory search", version="0.1.0")
    store = Store(db_path)
    app.state.store = store

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _HTML

    @app.get("/api/search")
    def api_search(
        q: str = Query("", description="search query"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        try:
            result = search(store, q, limit=limit, offset=offset)
        except QueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.to_dict()

    @app.get("/api/host/{ip}")
    def api_host(ip: str) -> dict[str, Any]:
        host = store.get_host(ip)
        if host is None:
            raise HTTPException(status_code=404, detail=f"no data for {ip}")
        host["findings"] = [f.to_dict() for f in analyze_rows(host["services"])]
        return host

    @app.get("/api/stats")
    def api_stats() -> dict[str, Any]:
        return {
            "services": store.count(),
            "hosts": store.host_count(),
            "top_ports": store.port_breakdown(),
            "top_services": store.service_breakdown(),
        }

    @app.get("/api/findings")
    def api_findings(limit: int = Query(200, ge=1, le=2000)) -> dict[str, Any]:
        rows = []
        for i, row in enumerate(store.iter_all()):
            if i >= 5000:  # cap the scan for responsiveness
                break
            rows.append(row)
        findings = analyze_rows(rows)[:limit]
        return {"count": len(findings), "findings": [f.to_dict() for f in findings]}

    @app.exception_handler(QueryError)
    def _query_error(_req: Any, exc: QueryError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app
