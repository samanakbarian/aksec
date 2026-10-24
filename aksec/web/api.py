"""FastAPI application exposing search, host detail, stats and exposure findings.

Run with::

    uvicorn 'aksec.web.api:create_app' --factory

or via the CLI: ``aksec serve``.

Authentication: if an auth config with keys is active (see aksec.auth), every
``/api`` request must carry a valid ``X-API-Key`` header and is served from
that key's tenant database. With no keys configured the API runs in open mode
against a single store.
"""

from __future__ import annotations

import io
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from ..analysis import analyze_rows
from ..auth import AuthConfig, load_auth
from ..export import export as export_inventory
from ..query import QueryError
from ..search import search
from ..storage import Store

_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


class StoreRegistry:
    """Opens and caches one Store per tenant (or a single open-mode store)."""

    def __init__(self, auth: AuthConfig, open_db_path: str):
        self._auth = auth
        self._open_db_path = open_db_path
        self._stores: dict[str, Store] = {}
        self._lock = threading.Lock()

    def for_tenant(self, tenant: str | None) -> Store:
        key = tenant or "__open__"
        with self._lock:
            if key not in self._stores:
                if tenant is None:
                    path = self._open_db_path
                else:
                    db = self._auth.db_path_for(tenant)
                    db.parent.mkdir(parents=True, exist_ok=True)
                    path = str(db)
                self._stores[key] = Store(path)
            return self._stores[key]

    def close(self) -> None:
        with self._lock:
            for store in self._stores.values():
                store.close()
            self._stores.clear()


def create_app(db_path: str = "aksec.db", auth: AuthConfig | None = None) -> FastAPI:
    auth = auth if auth is not None else load_auth()
    registry = StoreRegistry(auth, db_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        registry.close()

    app = FastAPI(
        title="aksec",
        description="Attack-surface inventory search",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.state.auth = auth
    app.state.registry = registry

    def get_store(x_api_key: str | None = Header(default=None)) -> Store:
        if not auth.enabled:
            return registry.for_tenant(None)
        tenant = auth.tenant_for(x_api_key)
        if tenant is None:
            raise HTTPException(status_code=401, detail="missing or invalid API key")
        return registry.for_tenant(tenant)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _HTML

    @app.get("/api/search")
    def api_search(
        q: str = Query("", description="search query"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        store: Store = Depends(get_store),
    ) -> dict[str, Any]:
        try:
            result = search(store, q, limit=limit, offset=offset)
        except QueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.to_dict()

    @app.get("/api/host/{ip}")
    def api_host(ip: str, store: Store = Depends(get_store)) -> dict[str, Any]:
        host = store.get_host(ip)
        if host is None:
            raise HTTPException(status_code=404, detail=f"no data for {ip}")
        host["findings"] = [f.to_dict() for f in analyze_rows(host["services"])]
        return host

    @app.get("/api/stats")
    def api_stats(store: Store = Depends(get_store)) -> dict[str, Any]:
        return {
            "services": store.count(),
            "hosts": store.host_count(),
            "top_ports": store.port_breakdown(),
            "top_services": store.service_breakdown(),
        }

    @app.get("/api/findings")
    def api_findings(
        limit: int = Query(200, ge=1, le=2000), store: Store = Depends(get_store)
    ) -> dict[str, Any]:
        rows = []
        for i, row in enumerate(store.iter_all()):
            if i >= 5000:  # cap the scan for responsiveness
                break
            rows.append(row)
        findings = analyze_rows(rows)[:limit]
        return {"count": len(findings), "findings": [f.to_dict() for f in findings]}

    @app.get("/api/export")
    def api_export(
        format: str = Query("ndjson", pattern="^(ndjson|csv)$"),
        store: Store = Depends(get_store),
    ) -> PlainTextResponse:
        buf = io.StringIO()
        export_inventory(store, buf, format)
        media = "application/x-ndjson" if format == "ndjson" else "text/csv"
        return PlainTextResponse(buf.getvalue(), media_type=media)

    @app.exception_handler(QueryError)
    def _query_error(_req: Any, exc: QueryError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app
