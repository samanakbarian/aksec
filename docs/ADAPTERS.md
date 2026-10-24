# Collector adapters

Adapters live in `aksec/adapters/` and do one thing: **transform output a tool
has already produced into the NDJSON ingest contract** (see
[`DATA_SCHEMA.md`](DATA_SCHEMA.md)). They perform no network activity — they
read a file and emit `Observation` records. This keeps all active data
collection outside this repository while still letting authorised results flow
in.

## nmap

Convert `nmap -oX` XML output:

```bash
nmap -oX scan.xml -sV 198.51.100.0/24      # run elsewhere, with authorisation
aksec import-nmap scan.xml --db demo.db     # pure conversion, no scanning
```

Only ports in state `open` are imported. Service product/version/extrainfo
become the banner, and the raw detail is kept under `data.nmap_service`. The
scan start time becomes `observed_at`, so history works correctly.

## Writing a new adapter

An adapter is just a function that yields `Observation` objects:

```python
from aksec.models import Observation

def parse_myformat(source) -> Iterator[Observation]:
    for record in ...:
        yield Observation(ip=..., port=..., service=..., source="mytool", data={...})
```

Wire it into the CLI next to `import-nmap`, or import it directly and call
`store.bulk_upsert(...)`. Because the boundary is the `Observation` model,
nothing downstream needs to know where the data came from.
