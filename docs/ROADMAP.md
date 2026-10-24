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

- [ ] IPv6 support across models, storage and query
- [ ] Historical observations (keep versions over time; show "first/last seen")
- [ ] More findings: default credentials indicators, known-vulnerable version
      ranges, missing security headers (HSTS/CSP), open directory listings
- [ ] Saved searches and simple alerting ("tell me when a new 3389 appears")
- [ ] Authentication and per-tenant data isolation on the API
- [ ] Export: NDJSON / CSV out, not just in
- [ ] Collector adapter examples that *transform existing tool output* into the
      ingest contract (no new scanning logic in this repo)

## Medium term (v0.3+)

- [ ] Pluggable storage backend (PostgreSQL + OpenSearch/ClickHouse) behind the
      existing `Store` interface
- [ ] Batch analysis job writing findings to a derived table
- [ ] Asset grouping / tagging (by team, environment, business unit)
- [ ] Diffing: "what changed on my attack surface since last week"
- [ ] Web UI: facets, pagination, host timeline, finding triage/acknowledge
- [ ] Role-based access control

## Explicitly out of scope for this repository

- Internet-wide scanning and active data collection. aksec consumes the
  ingest contract; producing it from authorised sources is a separate concern.
  See [`ETHICS.md`](ETHICS.md).
