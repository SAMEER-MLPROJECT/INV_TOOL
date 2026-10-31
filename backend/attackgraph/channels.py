"""Multichannel corroboration analysis.

Every record comes from one *observation channel*: identity, endpoint, network, DNS, data or
detection. A conclusion that several independent channels saw is stronger than one that a
single channel reported many times. This module answers, for every attack-path step and every
incident entity:

* which channels **saw** it (the primary record, plus corroborating records within ± 15 min);
* which channels **should** have seen it, given the kind of step (expectation table below);
* where an expected channel was **silent** although it covers that entity (an evidence gap:
  logging failure, tampering or simply benign absence — the analyst must decide);
* where an expected channel is **blind** because it never covers that entity (a coverage gap,
  not suspicious in itself).

Channel agreement = Σ evidenced expected channels / Σ expected channels (over steps). It is a
descriptive measure of how well-corroborated a hypothesis is, not a probability.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from datetime import datetime, timedelta

from .models import EntityType, NormalizedEvent, RelType

CHANNELS = ["identity", "endpoint", "network", "dns", "data", "detection"]
CHANNEL_LABELS = {"identity": "Identity", "endpoint": "Endpoint", "network": "Network", "dns": "DNS",
                  "data": "Data", "detection": "Detection"}
BY_SOURCE = {"idp_auth": "identity", "edr": "endpoint", "firewall": "network", "dns": "dns", "db_audit": "data",
             "siem_alerts": "detection"}
BY_CATEGORY = {"authentication": "identity", "process": "endpoint", "privilege": "endpoint", "service": "endpoint",
               "network": "network", "dns": "dns", "db_access": "data", "alert": "detection"}
STEP_WINDOW = timedelta(minutes=15)

# Which channels would normally also observe each kind of step (detection is never "expected").
EXPECTED: dict[RelType, set[str]] = {
    RelType.AUTHENTICATED_TO: {"identity", "endpoint"},
    RelType.EXECUTED: {"endpoint"},
    RelType.SPAWNED: {"endpoint"},
    RelType.CONNECTED_TO: {"network", "endpoint"},
    RelType.COMMUNICATED_WITH: {"network", "endpoint", "dns"},
    RelType.ACCESSED: {"data", "network"},
    RelType.QUERIED: {"dns"},
    RelType.RESOLVED_TO: {"dns"},
    RelType.PRIVILEGE_ESCALATED: {"endpoint", "identity"},
    RelType.MODIFIED: {"endpoint"},
}


def channel_of(ev: NormalizedEvent) -> str:
    return BY_SOURCE.get(ev.source_system) or BY_CATEGORY.get(ev.category, "endpoint")


class ChannelIndex:
    """Per-entity, per-channel time index (processes are folded into their host)."""

    def __init__(self, g) -> None:
        self.g = g
        self.times: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        self.uids: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.coverage: dict[str, set[str]] = defaultdict(set)
        rows = []
        for uid, ev in g.events.items():
            ch = channel_of(ev)
            for ent in {self.anchor(e) for e in g.event_elements.get(uid, ()) if e in g.entities}:
                rows.append((ent, ch, ev.timestamp, uid))
        rows.sort(key=lambda r: (r[0], r[1], r[2], r[3]))
        for ent, ch, ts, uid in rows:
            self.times[(ent, ch)].append(ts)
            self.uids[(ent, ch)].append(uid)
            self.coverage[ent].add(ch)

    def anchor(self, entity_id: str) -> str:
        ent = self.g.entities.get(entity_id)
        if ent is not None and ent.type == EntityType.PROCESS and ent.attributes.get("host"):
            return f"host:{ent.attributes['host']}"
        return entity_id

    def records(self, entity_id: str, channel: str, lo: datetime, hi: datetime) -> list[str]:
        key = (self.anchor(entity_id), channel)
        ts = self.times.get(key)
        if not ts:
            return []
        i, j = bisect.bisect_left(ts, lo), bisect.bisect_right(ts, hi)
        return self.uids[key][i:j]


def index_for(g) -> ChannelIndex:
    idx = getattr(g, "_channel_index", None)
    if idx is None:
        idx = ChannelIndex(g)
        g._channel_index = idx
    return idx


def analyse_path(g, path: dict) -> dict:
    """Channel matrix for the steps of an explained attack path (output of graph.paths)."""
    idx = index_for(g)
    steps_out = []
    expected_total = evidenced_total = 0
    union: set[str] = set()
    gaps: list[str] = []
    for n, step in enumerate(path["steps"], start=1):
        rel = g.rels[step["relationship_id"]]
        t = datetime.fromisoformat(step["timestamp"])
        primary = channel_of(g.events[step["event_uid"]])
        ends = [rel.source, rel.target]
        expected = set(EXPECTED.get(rel.type, set())) | {primary}
        cells = {}
        for ch in CHANNELS:
            recs = sorted({u for e in ends for u in idx.records(e, ch, t - STEP_WINDOW, t + STEP_WINDOW)} - {step["event_uid"]})
            covered = any(ch in idx.coverage[idx.anchor(e)] for e in ends)
            if ch == primary:
                state = "primary"
            elif recs:
                state = "corroborating"
            elif ch in expected and covered:
                state = "silent"
                gaps.append(f"step {n} ({rel.type.value}): {CHANNEL_LABELS[ch]} covers "
                            f"{' / '.join(idx.anchor(e).split(':', 1)[1] for e in ends if ch in idx.coverage[idx.anchor(e)])} "
                            f"but recorded nothing within ±15 min")
            elif ch in expected:
                state = "blind"
            else:
                state = "none"
            cells[ch] = {"state": state, "records": recs[:5], "count": len(recs) + (1 if state == "primary" else 0),
                         "expected": ch in expected}
        ev_channels = {c for c, v in cells.items() if v["state"] in ("primary", "corroborating")}
        union |= ev_channels
        expected_total += len(expected)
        evidenced_total += len(expected & ev_channels)
        steps_out.append({"step": n, "relationship": rel.type.value, "from": rel.source, "to": rel.target,
                          "timestamp": step["timestamp"], "cells": cells, "channels_with_evidence": len(ev_channels)})
    agreement = round(evidenced_total / expected_total, 3) if expected_total else 0.0
    multi = sum(1 for s in steps_out if s["channels_with_evidence"] >= 2)
    return {
        "channels": CHANNELS, "labels": CHANNEL_LABELS, "steps": steps_out,
        "agreement": agreement, "independent_channels": sorted(union, key=CHANNELS.index),
        "multichannel_steps": multi, "single_channel_steps": len(steps_out) - multi,
        "silent_gaps": gaps,
        "summary": (f"{len(union)} independent channels; {multi} of {len(steps_out)} steps seen by two or more; "
                    f"channel agreement {agreement:.0%}; {len(gaps)} expected-but-silent observation(s)."),
    }


def analyse_incident(g, incident: dict, window: timedelta) -> dict:
    """Entity x channel matrix over the incident window (records touching each entity)."""
    idx = index_for(g)
    lo = datetime.fromisoformat(incident["start"]) - window
    hi = datetime.fromisoformat(incident["end"]) + window
    rows = []
    blind, silent = [], []
    for etype in ("user", "host", "database", "service", "ip"):
        for e in incident["entities"].get(etype, []):
            cells = {}
            for ch in CHANNELS:
                n = len(idx.records(e, ch, lo, hi))
                covered = ch in idx.coverage[idx.anchor(e)]
                state = "evidence" if n else ("silent" if covered else "blind")
                cells[ch] = {"count": n, "state": state}
            got = [c for c in CHANNELS if cells[c]["state"] == "evidence"]
            quiet = [c for c in CHANNELS if cells[c]["state"] == "silent" and c != "detection"]
            if quiet:
                silent.append(f"{e.split(':', 1)[1]}: {', '.join(CHANNEL_LABELS[c] for c in quiet)} normally observe this "
                              f"entity but recorded nothing in the incident window")
            rows.append({"entity": e, "cells": cells, "channels_with_evidence": len(got)})
    used = {c for r in rows for c in CHANNELS if r["cells"][c]["state"] == "evidence"}
    covering = {c for r in rows for c in CHANNELS if r["cells"][c]["state"] != "blind"}
    single = [r["entity"] for r in rows if r["channels_with_evidence"] == 1]
    if single:
        blind.append(f"{len(single)} entit{'y' if len(single) == 1 else 'ies'} seen by a single channel only: "
                     + ", ".join(s.split(':', 1)[1] for s in single[:6]))
    agreement = round(len(used) / len(covering), 3) if covering else 0.0
    return {
        "channels": CHANNELS, "labels": CHANNEL_LABELS, "rows": rows, "window": {"start": lo.isoformat(), "end": hi.isoformat()},
        "channels_with_evidence": sorted(used, key=CHANNELS.index), "agreement": agreement,
        "silent_observations": silent, "single_channel_entities": blind,
        "summary": (f"{len(used)} of {len(covering)} covering channels produced evidence for this incident "
                    f"({agreement:.0%}); {len(silent)} entit{'y has' if len(silent) == 1 else 'ies have'} expected-but-silent channels."),
    }
