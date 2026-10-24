# Authentication and multi-tenancy

aksec supports two API modes.

## Open mode (default)

With no auth config, the API requires no key and serves a single database (the
`--db` path). This is the right choice for local, single-user analysis.

```bash
aksec serve --db demo.db
```

## Multi-tenant mode

Provide an auth config and the API switches to **key-per-tenant** with
**isolation by database**: each tenant's data lives in its own SQLite file
under `data_dir`, so no query can cross tenant boundaries.

`config/auth.example.json`:

```json
{
  "data_dir": "data",
  "keys": {
    "replace-with-a-long-random-secret-for-acme": "acme",
    "replace-with-a-long-random-secret-for-globex": "globex"
  }
}
```

```bash
aksec serve --auth config/auth.example.json
# or point at it via the environment:
AKSEC_AUTH=config/auth.example.json aksec serve
```

Every `/api` request must then send the key:

```bash
curl -H "X-API-Key: <secret>" http://127.0.0.1:8000/api/stats
```

Requests without a valid key get `401`. The tenant's database is
`<data_dir>/<tenant>.db`, created on first use.

## Loading data per tenant

Because each tenant is a separate database file, the CLI loads data by simply
pointing `--db` at that file:

```bash
aksec import acme-scan.ndjson      --db data/acme.db
aksec import-nmap globex-scan.xml  --db data/globex.db
```

## Notes and limits

- Tenant names are restricted to `[A-Za-z0-9_-]` (max 64 chars) so they are
  safe as filenames.
- Keep the auth config out of version control and use long, random keys. Serve
  over TLS (e.g. behind a reverse proxy) so keys are not sent in the clear.
- This is tenant *isolation*, not full RBAC. Per-user roles within a tenant are
  on the roadmap.
