# Data schema — the ingest contract

aksec ingests **newline-delimited JSON (NDJSON)**: one JSON object per line,
each describing a single service observed on one host. This is the contract
any collector must produce, and the boundary the rest of the platform depends
on. It is intentionally collector-agnostic — the component that *produces*
these records (an authorised internal scanner, an export adapter for an
existing tool, a partner feed) is deliberately out of scope for this layer.

## Observation object

| Field         | Type     | Required | Description                                           |
|---------------|----------|----------|-------------------------------------------------------|
| `ip`          | string   | yes      | IPv4 address of the host                              |
| `port`        | integer  | yes      | 1–65535                                               |
| `transport`   | string   | no       | `tcp` (default) or `udp`                              |
| `service`     | string   | no       | normalised service name, e.g. `https`, `ssh`         |
| `banner`      | string   | no       | first bytes the service returned, if any              |
| `observed_at` | string   | no       | ISO-8601 timestamp (UTC); defaults to now             |
| `source`      | string   | no       | which feed/collector produced this record             |
| `data`        | object   | no       | protocol-specific detail (see below)                  |

The primary key is `(ip, port, transport)`: re-importing a fresher record for
the same tuple **updates in place**.

### `data` sub-objects (all optional)

```jsonc
{
  "tls": {
    "subject": "CN=www.example.com",
    "issuer": "CN=Example CA",
    "not_before": "2025-01-01T00:00:00Z",
    "not_after": "2026-01-01T00:00:00Z",
    "version": "TLSv1.3",
    "self_signed": false
  },
  "http": {
    "status_code": 200,
    "headers": { "Server": "nginx/1.24.0" }
  },
  "ssh": {
    "banner": "SSH-2.0-OpenSSH_9.6"
  }
}
```

The analysis layer reads known keys (`tls.not_after`, `tls.version`,
`http.headers`, …) to produce findings, but `data` may carry any additional
protocol detail — it is stored verbatim and is searchable via `has:` and
full-text search.

## Example

```json
{"ip":"198.51.100.10","port":443,"service":"https","source":"demo","banner":"nginx/1.24.0","data":{"tls":{"subject":"CN=www.example.com","not_after":"2026-01-01T00:00:00Z","version":"TLSv1.3"},"http":{"status_code":200,"headers":{"Server":"nginx/1.24.0"}}}}
```

Malformed lines are skipped and reported; one bad record never aborts an
import (see `aksec/ingest.py`).
