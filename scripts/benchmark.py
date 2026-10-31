#!/usr/bin/env python3
"""Measure wall-clock timings of the main operations on the synthetic dataset.

    python scripts/benchmark.py [--repeat 5]

Reports the median of N runs on the current machine. These numbers describe this
prototype on this dataset only; they are not a throughput claim for production data.
"""
from __future__ import annotations

import argparse
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from datetime import datetime  # noqa: E402

from attackgraph.correlate import correlate  # noqa: E402
from attackgraph.deviation import score_deviations  # noqa: E402
from attackgraph.graph.paths import PathQuery  # noqa: E402
from attackgraph.workspace import Workspace  # noqa: E402


def timed(fn, repeat):
    out = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return statistics.median(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=5)
    a = ap.parse_args()
    ws = Workspace()
    rows = [
        ("Ingest 7 files + build graph", timed(ws.load_sample, a.repeat)),
        ("Correlate alerts into incidents", timed(lambda: correlate(ws.graph, ws.settings), a.repeat)),
        ("Paths sameer -> FINANCE-DB (5 hops)", timed(lambda: ws.paths(PathQuery("user:sameer", ["database:FINANCE-DB"], 5)), a.repeat)),
        ("Paths sameer -> all critical (8 hops)", timed(lambda: ws.paths(PathQuery("user:sameer", None, 8)), a.repeat)),
        ("Blast radius sameer (4 hops, temporal)", timed(lambda: ws.blast("user:sameer", 4, True, None, True), a.repeat)),
        ("Blast radius WS-014 (8 hops, structural)", timed(lambda: ws.blast("host:WS-014", 8, False, None, True), a.repeat)),
        ("MD deviation scoring (all occurrences)", timed(lambda: score_deviations(ws.graph), a.repeat)),
        ("Multichannel analysis of incident INC-0002", timed(lambda: ws.incident_detail("INC-0002"), a.repeat)),
        ("Containment plan INC-0002 at first alert", timed(lambda: ws.containment("INC-0002"), a.repeat)),
        ("Containment plan INC-0002 at 21:10Z", timed(lambda: ws.containment("INC-0002", datetime.fromisoformat("2026-10-27T21:10:00+00:00")), a.repeat)),
    ]
    s = ws.summary()
    print(f"dataset: {s['events']} events, {s['entities']} entities, {s['relationships']} relationships, {s['occurrences']} occurrences")
    print(f"machine: {platform.platform()} · Python {platform.python_version()} · median of {a.repeat} runs")
    print("| Operation | Median (ms) |\n|---|---|")
    for name, ms in rows:
        print(f"| {name} | {ms:.1f} |")


if __name__ == "__main__":
    main()
