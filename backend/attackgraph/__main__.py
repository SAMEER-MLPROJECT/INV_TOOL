from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="attackgraph", description="AttackGraph Lens")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the API and web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    a = sub.add_parser("analyze", help="print a summary of a dataset directory")
    a.add_argument("--data", type=Path, default=None)
    p = sub.add_parser("path", help="find temporal attack paths between two entities")
    p.add_argument("source")
    p.add_argument("target", nargs="?")
    p.add_argument("--hops", type=int, default=5)
    p.add_argument("--data", type=Path, default=None)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from .config import load_env_file
    load_env_file()

    if args.cmd == "serve":
        import uvicorn

        from .api.app import create_app
        uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
        return 0

    from .graph.paths import PathQuery
    from .workspace import Workspace

    ws = Workspace()
    if getattr(args, "data", None):
        ws.load_directory(args.data)
    else:
        ws.load_sample()
    if args.cmd == "analyze":
        s = ws.summary()
        print(f"events={s['events']} entities={s['entities']} relationships={s['relationships']} "
              f"sources={s['source_systems']} incidents={s['incidents']}")
        for inc in ws.incidents:
            print(f"  {inc['id']} {inc['priority']:<8} {inc['score']:>5}  {inc['title']}")
        return 0
    res = ws.paths(PathQuery(source=args.source, targets=[args.target] if args.target else None, max_hops=args.hops))
    for path in res["paths"]:
        print(f"{path['score']:>5} {path['priority']:<8} " + " -> ".join(path["nodes"]))
    if res["rejected_temporally_impossible"]:
        print("rejected (temporally impossible):")
        for r in res["rejected_temporally_impossible"]:
            print("   " + " -> ".join(r["nodes"]) + f"\n      {r['reason']}")
    json.dump(res["search"], sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
