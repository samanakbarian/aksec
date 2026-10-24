# aksec

**Attack-surface inventory search** — a small, Censys-inspired platform for
*your own* assets. Load observations about hosts and services you own or are
authorised to assess, search them with a compact query language, inspect
individual hosts, and get advisory findings about risky exposure.

aksec does **not** scan the Internet. It is the storage, search, analysis and
presentation layer. Data comes in as NDJSON observations from whatever
collector you trust — an authorised internal scan, an export from an existing
tool, or a partner feed. See [`docs/DATA_SCHEMA.md`](docs/DATA_SCHEMA.md) for
the input contract.

> Only load data for networks you own or have explicit permission to assess.
> See [`docs/ETHICS.md`](docs/ETHICS.md).

## Quick start

```bash
pip install -e .

# Load the demo data
aksec import examples/sample.ndjson --db demo.db

# Or import from an existing nmap XML file (pure conversion, no scanning)
aksec import-nmap examples/nmap-sample.xml --db demo.db

# Explore from the command line
aksec stats     --db demo.db
aksec search port:443 --db demo.db
aksec search ip:198.51.100.0/24 --db demo.db
aksec search "seen_since:2026-01-01" --db demo.db
aksec findings  --db demo.db

# Export the inventory back out
aksec export --format csv   --db demo.db --out inventory.csv
aksec export --format ndjson --db demo.db > inventory.ndjson

# Or run the web UI + API
aksec serve --db demo.db           # http://127.0.0.1:8000
```

## Query language

| Term            | Meaning                                  |
|-----------------|------------------------------------------|
| `port:443`      | exact port                               |
| `port:8000-8100`| port range                               |
| `service:https` | service name                             |
| `ip:10.0.0.1`   | a single host                            |
| `ip:10.0.0.0/8` | all hosts in a CIDR                      |
| `banner:nginx`  | substring in the banner                  |
| `source:acme`   | which feed the data came from            |
| `has:tls`       | a `tls` block is present in the data     |
| `seen_since:2026-01-01` | last seen on/after a date        |
| `seen_before:2026-01-01`| last seen before a date          |
| `nginx 2.4`     | free words → full-text search            |

Terms are AND-ed. Every value is bound as a SQL parameter, so queries cannot
inject SQL.

## HTTP API

| Endpoint             | Description                               |
|----------------------|-------------------------------------------|
| `GET /api/search?q=` | search services (`limit`, `offset`)       |
| `GET /api/host/{ip}` | all services on a host + exposure findings|
| `GET /api/stats`     | counts and top ports/services             |
| `GET /api/findings`  | advisory exposure findings                |
| `GET /api/export?format=csv` | export inventory (`ndjson`/`csv`) |

## Layout

```
aksec/
  config.py      runtime settings (env-driven)
  models.py      Observation schema (the ingest contract)
  targets.py     IP/CIDR + port expansion with exclusions
  storage.py     SQLite store (services + FTS index)
  query.py       query-language -> safe parameterised SQL
  search.py      high-level search
  analysis.py    exposure heuristics (findings)
  ingest.py      NDJSON loader
  export.py      NDJSON / CSV export
  adapters/      transform existing tool output (e.g. nmap XML) into the contract
  cli.py         command-line interface
  web/           FastAPI app + single-page UI
docs/            architecture, roadmap, data schema, ethics
examples/        sample NDJSON data
tests/           pytest suite
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Tests

```bash
pip install -e ".[dev]"
pytest
```
