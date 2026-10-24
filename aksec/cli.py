"""Command-line interface for aksec.

    aksec import FILE [--db PATH]     load NDJSON observations
    aksec search QUERY [--db PATH]    run a search query
    aksec stats [--db PATH]           show inventory statistics
    aksec findings [--db PATH]        list exposure findings
    aksec serve [--host H --port P]   run the web UI + API
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .analysis import analyze_rows
from .ingest import ingest_file
from .query import QueryError
from .search import search
from .storage import Store


def _add_db(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", default="aksec.db", help="path to the SQLite database")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aksec", description="Attack-surface inventory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_import = sub.add_parser("import", help="load NDJSON observations into the store")
    p_import.add_argument("file", help="path to an NDJSON file ('-' for stdin)")
    _add_db(p_import)

    p_search = sub.add_parser("search", help="search the inventory")
    p_search.add_argument("query", nargs="*", help="query terms")
    p_search.add_argument("--limit", type=int, default=50)
    p_search.add_argument("--json", action="store_true", help="output raw JSON")
    _add_db(p_search)

    p_stats = sub.add_parser("stats", help="show inventory statistics")
    _add_db(p_stats)

    p_find = sub.add_parser("findings", help="list exposure findings")
    _add_db(p_find)

    p_export = sub.add_parser("export", help="export the inventory to NDJSON or CSV")
    p_export.add_argument("--format", choices=["ndjson", "csv"], default="ndjson")
    p_export.add_argument("--out", help="output file (default: stdout)")
    _add_db(p_export)

    p_nmap = sub.add_parser("import-nmap", help="import nmap XML output (no scanning)")
    p_nmap.add_argument("file", help="path to an nmap XML file ('-' for stdin)")
    p_nmap.add_argument("--source", default="nmap", help="value for the 'source' field")
    _add_db(p_nmap)

    p_watch = sub.add_parser("watch", help="saved searches and simple alerting")
    wsub = p_watch.add_subparsers(dest="watch_cmd", required=True)
    w_add = wsub.add_parser("add", help="save a named search")
    w_add.add_argument("name")
    w_add.add_argument("query", nargs="+")
    _add_db(w_add)
    w_list = wsub.add_parser("list", help="list saved searches")
    _add_db(w_list)
    w_del = wsub.add_parser("rm", help="delete a saved search")
    w_del.add_argument("name")
    _add_db(w_del)
    w_run = wsub.add_parser("run", help="run a saved search and report what changed")
    w_run.add_argument("name")
    _add_db(w_run)

    p_serve = sub.add_parser("serve", help="run the web UI and API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--auth", help="path to an auth config (enables multi-tenant API-key mode)")
    _add_db(p_serve)

    return parser


def cmd_import(args: argparse.Namespace) -> int:
    with Store(args.db) as store:
        if args.file == "-":
            from .ingest import ingest_stream

            report = ingest_stream(store, sys.stdin)
        else:
            report = ingest_file(store, args.file)
    print(report.summary())
    for err in report.errors[:10]:
        print(f"  ! {err}", file=sys.stderr)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    query = " ".join(args.query)
    with Store(args.db) as store:
        try:
            result = search(store, query, limit=args.limit)
        except QueryError as exc:
            print(f"query error: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0
    print(f"{result.total} result(s):")
    for s in result.services:
        extra = ""
        if s["data"].get("tls", {}).get("subject"):
            extra = f"  [{s['data']['tls']['subject']}]"
        print(f"  {s['ip']}:{s['port']}  {s['service']}/{s['transport']}  ({s['source']}){extra}")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    with Store(args.db) as store:
        print(f"hosts:    {store.host_count()}")
        print(f"services: {store.count()}")
        print("top ports:")
        for row in store.port_breakdown(10):
            print(f"  {row['port']:>6}  {row['count']}")
        print("top services:")
        for row in store.service_breakdown(10):
            print(f"  {row['service']:>12}  {row['count']}")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    with Store(args.db) as store:
        rows = list(store.iter_all())
    findings = analyze_rows(rows)
    if not findings:
        print("no findings")
        return 0
    for f in findings:
        print(f"  [{f.severity:>6}] {f.ip}:{f.port}  {f.code}  {f.message}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .export import export

    with Store(args.db) as store:
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="") as fh:
                n = export(store, fh, args.format)
            print(f"exported {n} record(s) to {args.out}", file=sys.stderr)
        else:
            n = export(store, sys.stdout, args.format)
    return 0


def cmd_import_nmap(args: argparse.Namespace) -> int:
    from .adapters.nmap import parse_nmap_xml

    src = sys.stdin if args.file == "-" else open(args.file, "r", encoding="utf-8")
    try:
        observations = list(parse_nmap_xml(src, default_source=args.source))
    finally:
        if src is not sys.stdin:
            src.close()
    with Store(args.db) as store:
        n = store.bulk_upsert(observations)
    print(f"imported {n} open service(s) from nmap XML")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from . import watch

    with Store(args.db) as store:
        if args.watch_cmd == "add":
            query = " ".join(args.query)
            try:
                watch.add_watch(store, args.name, query)
            except QueryError as exc:
                print(f"query error: {exc}", file=sys.stderr)
                return 2
            print(f"saved search {args.name!r}: {query}")
        elif args.watch_cmd == "list":
            rows = watch.list_watches(store)
            if not rows:
                print("no saved searches")
            for r in rows:
                print(f"  {r['name']:<20} tracked={r['tracked']:<5} last_run={r['last_run'] or 'never'}  {r['query']}")
        elif args.watch_cmd == "rm":
            print("deleted" if store.delete_search(args.name) else "no such search")
        elif args.watch_cmd == "run":
            try:
                result = watch.run_watch(store, args.name)
            except KeyError:
                print(f"no such search: {args.name}", file=sys.stderr)
                return 2
            if result.first_run:
                print(f"{result.name}: baseline captured ({result.total} service(s)); future runs report changes")
            else:
                print(f"{result.name}: {result.total} match(es), "
                      f"{len(result.appeared)} new, {len(result.disappeared)} gone")
                for s in result.appeared:
                    print(f"  + {s['ip']}:{s['port']}  {s['service']}/{s['transport']}  ({s['source']})")
                for key in result.disappeared:
                    ip, port, transport = key.split("|")
                    print(f"  - {ip}:{port}  {transport}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .auth import load_auth
    from .web.api import create_app

    auth = load_auth(args.auth) if args.auth else load_auth()
    if auth.enabled:
        print(f"auth: multi-tenant mode, {len(auth.keys)} key(s), data dir {auth.data_dir}")
    else:
        print("auth: open mode (no API key required)")
    app = create_app(args.db, auth=auth)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


_HANDLERS = {
    "import": cmd_import,
    "import-nmap": cmd_import_nmap,
    "search": cmd_search,
    "stats": cmd_stats,
    "findings": cmd_findings,
    "export": cmd_export,
    "watch": cmd_watch,
    "serve": cmd_serve,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _HANDLERS[args.cmd](args)
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `... | head`); exit quietly.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
