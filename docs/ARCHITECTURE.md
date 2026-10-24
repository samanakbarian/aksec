# Architecture

aksec separates **data collection** from **everything you do with the data**.
This repository implements the second half: a durable store, a query language,
exposure analysis, an API and a UI. Collection is a pluggable producer that
feeds the ingest contract in [`DATA_SCHEMA.md`](DATA_SCHEMA.md).

```
             ┌──────────────┐
  collectors │  (external)  │   authorised scan / tool export / partner feed
  ───────────┴──────┬───────┘
                    │  NDJSON observations
                    ▼
            ┌───────────────┐
            │   ingest.py   │  parse, validate, report bad lines
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │  storage.py   │  SQLite: `service` table + FTS5 index
            └───┬───────┬───┘
                │       │
      ┌─────────▼──┐  ┌─▼──────────┐
      │  query.py  │  │ analysis.py│  exposure heuristics -> findings
      │ search.py  │  └─────┬──────┘
      └─────┬──────┘        │
            ▼               ▼
        ┌───────────────────────┐
        │   web/api.py (FastAPI) │  /api/search /api/host /api/stats /api/findings
        │   web/index.html (UI)  │
        │   cli.py               │  import / search / stats / findings / serve
        └───────────────────────┘
```

## Components

- **`models.py`** — the `Observation` pydantic model. The single source of
  truth for the ingest contract; validation lives here.
- **`storage.py`** — a SQLite store. One `service` row per
  `(ip, port, transport)`, upserted on re-import. A standalone FTS5 table
  (`service_fts`) indexes banners and the raw `data` JSON for free-text
  search. All access is serialised through a lock so a single connection is
  safe under the FastAPI thread pool.
- **`query.py`** — compiles the query language to a parameterised SQL `WHERE`
  clause. Field terms map to indexed columns; free text maps to an FTS5
  `MATCH`. Values are always bound, never interpolated.
- **`analysis.py`** — stateless heuristics over service rows. Each returns a
  list of `Finding`s (severity, code, message). Purely advisory.
- **`web/`** — a thin FastAPI app plus a dependency-free single-page UI.
- **`targets.py`** — target-set maths (CIDR + port expansion, exclusions,
  scattered iteration order). Useful to a collector for deciding *what* to
  look at; carries the reserved-range and blocklist exclusions.

## Why SQLite

For an MVP and for per-team inventories (thousands to low millions of
services) SQLite with an FTS5 index is simple, fast, dependency-free and
trivially portable. The store is deliberately behind a small interface
(`Store`), so swapping in PostgreSQL + a search engine (see
[`ROADMAP.md`](ROADMAP.md)) is a localised change: the API, query compiler and
analysis layers do not depend on SQLite specifics beyond `Store`'s methods.

## Scaling beyond one node

The clean seam is the **NDJSON ingest contract**. At larger scale you would:

1. Run collectors as independent producers writing to a queue/object store.
2. Replace `Store` with a columnar/search backend (Postgres + OpenSearch, or
   ClickHouse) behind the same method surface.
3. Keep `query.py` as the compiler, re-targeting its output to the new backend.
4. Make analysis a batch job that writes findings back as a derived table.

The API and UI stay unchanged because they only speak to `Store`,
`search()` and `analyze_rows()`.
