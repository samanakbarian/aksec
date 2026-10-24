# Roadmap

Status of this repository: a working MVP of the **data, search, analysis and
presentation** layers. Collection is intentionally out of scope here and is
represented only by the ingest contract.

## Done (v0.1)

- [x] Observation schema and NDJSON ingest with per-line error reporting
- [x] SQLite store with upsert-in-place and an FTS5 full-text index
- [x] Query language → safe parameterised SQL (`port`, `service`, `ip`/CIDR,
      `banner`, `source`, `has:`, free text)
- [x] Exposure analysis (sensitive ports, TLS expiry/weak version/self-signed,
      plaintext HTTP, server-banner disclosure)
- [x] FastAPI API: search, host detail + findings, stats, findings
- [x] Dependency-free single-page web UI
- [x] CLI: import / search / stats / findings / serve
- [x] Target-set maths with reserved-range and blocklist exclusions
- [x] pytest suite (24 tests)

## Near term (v0.2)

- [x] Historical observations: `first_seen` / `last_seen` per service, with
      `seen_since:` / `seen_before:` query fields (and a schema migration for
      pre-0.2 databases)
- [x] More findings: missing security headers (HSTS/CSP), open directory
      listings, obsolete SSH protocol 1
- [x] Export: NDJSON / CSV out (CLI `export` + `GET /api/export`)
- [x] Collector adapter that *transforms existing tool output* into the ingest
      contract — nmap XML (`import-nmap`), no scanning logic in this repo
- [x] IPv6 support across models, storage and query (single address and CIDR,
      via an `ip_in_cidr` SQL function that handles v4 and v6)
- [x] Known-vulnerable version ranges: a small curated `vulndb` turning service
      versions into `known-vuln` findings (pluggable with a real feed later)
- [x] Saved searches and simple alerting (`watch add/list/run/rm`): each run
      reports services that appeared or disappeared since the last run
- [x] Authentication and per-tenant data isolation on the API: `X-API-Key` →
      tenant, each tenant in its own database; open mode when no keys are set
- [ ] Default-credential indicators

## Medium term (v0.3+)

- [ ] Pluggable storage backend (PostgreSQL + OpenSearch/ClickHouse) behind the
      existing `Store` interface
- [ ] Replace the curated `vulndb` with a real feed (NVD / OSV) behind the same
      `match_version()` interface
- [ ] Batch analysis job writing findings to a derived table
- [ ] Asset grouping / tagging (by team, environment, business unit)
- [ ] Diffing: "what changed on my attack surface since last week"
- [ ] Web UI: facets, pagination, host timeline, finding triage/acknowledge,
      multi-tenant login
- [ ] Role-based access control (beyond per-tenant isolation)
- [ ] Scheduled alerting: run saved searches on a timer and notify

## Explicitly out of scope for this repository

- Internet-wide scanning and active data collection. aksec consumes the
  ingest contract; producing it from authorised sources is a separate concern.
  See [`ETHICS.md`](ETHICS.md).
