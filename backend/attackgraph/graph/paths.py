from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

import networkx as nx

from ..config import AnalysisSettings
from ..models import TRAVERSABLE, Basis, EntityType, Relationship, RelType
from ..narrative import describe_event
from ..risk import corroboration_factor, length_factor, recency_factor, score
from .builder import TemporalGraph

HARD_MAX_HOPS = 8
MAX_CANDIDATES = 3000
MAX_REJECTED = 15

CandidateProvider = Callable[[str, str, int], list[list[str]]]


@dataclass
class PathQuery:
    source: str
    targets: list[str] | None = None
    max_hops: int = 5
    max_paths: int = 12
    rel_types: set[RelType] | None = None
    since: datetime | None = None


@dataclass
class _Search:
    expansions: int = 0
    truncated: bool = False
    candidates: list[list[str]] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)


class PathError(ValueError):
    pass


@dataclass(frozen=True)
class Window:
    skew: timedelta
    gap: timedelta | None

    @classmethod
    def from_settings(cls, s: AnalysisSettings) -> "Window":
        gap = timedelta(hours=s.max_hop_gap_hours) if s.max_hop_gap_hours > 0 else None
        return cls(timedelta(seconds=s.clock_skew_seconds), gap)


def default_targets(g: TemporalGraph, source: str) -> list[str]:
    return sorted(
        e.id for e in g.entities.values()
        if e.id != source and e.criticality >= 4 and e.type in (EntityType.HOST, EntityType.DATABASE, EntityType.USER)
    )


def _fmt(t: datetime | None) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%SZ") if t else "-"


def _times(g: TemporalGraph, rel: Relationship) -> list[datetime]:
    return g._times.get(rel.id) or [o.timestamp for o in rel.occurrences]


def first_hop(g: TemporalGraph, rel: Relationship, since: datetime | None, w: Window) -> list[int]:
    times = _times(g, rel)
    lo = 0 if since is None else bisect.bisect_left(times, since - w.skew)
    return list(range(lo, len(times)))


def extend(g: TemporalGraph, prev_times: list[datetime], rel: Relationship, w: Window) -> list[int]:
    out = []
    if not prev_times:
        return out
    earliest, latest = prev_times[0], prev_times[-1]
    times = _times(g, rel)
    start = bisect.bisect_left(times, earliest - w.skew)
    for j in range(start, len(times)):
        t = times[j]
        if w.gap is not None and t > latest + w.gap:
            break
        lo_s = t - w.gap if w.gap is not None else None
        i = 0 if lo_s is None else bisect.bisect_left(prev_times, lo_s)
        if i < len(prev_times) and prev_times[i] <= t + w.skew:
            out.append(j)
    return out


def _explain_infeasible(g: TemporalGraph, prev_times: list[datetime], rel: Relationship, hop: int, w: Window) -> str:
    times = _times(g, rel)
    gap = f"{w.gap.total_seconds() / 3600:g} h" if w.gap is not None else "unlimited"
    if times and times[-1] < prev_times[0] - w.skew:
        why = f"its latest occurrence {_fmt(times[-1])} is before the earliest possible arrival {_fmt(prev_times[0])}"
    else:
        why = (f"none of its {len(times)} occurrences ({_fmt(times[0] if times else None)} .. {_fmt(times[-1] if times else None)}) "
               f"falls within the allowed window after an arrival ({_fmt(prev_times[0])} .. {_fmt(prev_times[-1])}; max gap {gap})")
    return f"hop {hop} ({rel.type.value} {rel.source} -> {rel.target}): {why}"


def schedule(g: TemporalGraph, rels: list[Relationship], since: datetime | None, w: Window) -> tuple[list[int] | None, str | None]:
    sets: list[list[int]] = []
    prev: list[datetime] | None = None
    for i, rel in enumerate(rels):
        idx = first_hop(g, rel, since, w) if i == 0 else extend(g, prev or [], rel, w)
        if not idx:
            if i == 0:
                return None, f"hop 1 ({rel.type.value} {rel.source} -> {rel.target}): no occurrence after {_fmt(since)}"
            return None, _explain_infeasible(g, prev or [], rel, i + 1, w)
        sets.append(idx)
        prev = [rel.occurrences[j].timestamp for j in idx]
    chosen = [0] * len(rels)
    nxt_t: datetime | None = None
    for i in range(len(rels) - 1, -1, -1):
        occ = rels[i].occurrences
        cand = sets[i]
        if nxt_t is not None:
            cand = [j for j in cand if occ[j].timestamp <= nxt_t + w.skew
                    and (w.gap is None or occ[j].timestamp >= nxt_t - w.gap)]
        best = max(cand, key=lambda j: (occ[j].suspicion, occ[j].timestamp if nxt_t is not None else -j))
        chosen[i] = best
        nxt_t = occ[best].timestamp
    return chosen, None


def _dfs(g: TemporalGraph, q: PathQuery, targets: set[str], st: _Search, settings: AnalysisSettings) -> None:
    w = Window.from_settings(settings)
    allowed = q.rel_types or TRAVERSABLE

    def out_rels(node: str) -> list[Relationship]:
        rels = [g.rels[d["rel_id"]] for _, _, d in g.g.out_edges(node, data=True)]
        rels = [r for r in rels if r.type in allowed]
        rels.sort(key=lambda r: (-r.max_suspicion, -g.entities[r.target].criticality, r.id))
        return rels

    def visit(node: str, arrivals: list[datetime] | None, path_rels: list[str], on_path: set[str]) -> None:
        if st.truncated or len(path_rels) >= q.max_hops:
            return
        for rel in out_rels(node):
            if st.truncated:
                return
            st.expansions += 1
            if st.expansions > settings.search_budget or len(st.candidates) >= MAX_CANDIDATES:
                st.truncated = True
                return
            if rel.target in on_path:
                continue
            idx = first_hop(g, rel, q.since, w) if arrivals is None else extend(g, arrivals, rel, w)
            if not idx:
                if rel.target in targets and len(st.rejected) < MAX_REJECTED:
                    rels_seq = [g.rels[r] for r in path_rels] + [rel]
                    nodes = [q.source] + [r.target for r in rels_seq]
                    if not any(x["nodes"] == nodes for x in st.rejected):
                        _, reason = schedule(g, rels_seq, q.since, w)
                        st.rejected.append({"nodes": nodes, "relationships": [r.id for r in rels_seq],
                                            "reason": reason or "temporal ordering violated"})
                continue
            new_rels = path_rels + [rel.id]
            if rel.target in targets:
                st.candidates.append(new_rels)
            on_path.add(rel.target)
            visit(rel.target, [rel.occurrences[j].timestamp for j in idx], new_rels, on_path)
            on_path.discard(rel.target)

    visit(q.source, None, [], {q.source})


def _explain_path(g: TemporalGraph, rel_ids: list[str], q: PathQuery, settings: AnalysisSettings) -> dict | None:
    w = Window.from_settings(settings)
    rels = [g.rels[r] for r in rel_ids]
    chosen, _ = schedule(g, rels, q.since, w)
    if chosen is None:
        return None
    steps = []
    sources: set[str] = set()
    susp: list[float] = []
    observed = 0
    for rel, idx in zip(rels, chosen):
        occ = rel.occurrences[idx]
        ev = g.events.get(occ.event_uid)
        sources.add(occ.source_system)
        alert_id = occ.attributes.get("alert")
        if alert_id:
            sources.add("siem_alerts")
        susp.append(occ.suspicion)
        observed += occ.basis == Basis.OBSERVED
        steps.append({
            "from": rel.source, "to": rel.target, "relationship": rel.type.value, "relationship_id": rel.id,
            "timestamp": occ.timestamp.isoformat(), "event_uid": occ.event_uid,
            "source_system": occ.source_system, "source_file": ev.source_file if ev else None,
            "source_row": ev.source_row if ev else None, "basis": occ.basis.value, "rule": occ.rule,
            "suspicion": round(occ.suspicion, 3), "suspicion_rule": occ.attributes.get("suspicion_rule"),
            "alert": alert_id, "description": describe_event(ev) if ev else "",
            "total_occurrences": len(rel.occurrences),
        })
    target = g.entities[rels[-1].target]
    first_t, last_t = rels[0].occurrences[chosen[0]].timestamp, rels[-1].occurrences[chosen[-1]].timestamp
    hops = len(rels)
    suspicious_hops = sum(1 for s in susp if s >= settings.suspicion_threshold)
    components = {
        "criticality": target.criticality / 5.0,
        "suspicion": sum(susp) / hops,
        "corroboration": corroboration_factor(len(sources)),
        "evidence_quality": observed / hops,
        "path_length": length_factor(hops),
        "recency": recency_factor(last_t, g.max_time, settings.recency_half_life_hours),
    }
    notes = {
        "criticality": f"target {target.name} criticality {target.criticality}/5",
        "suspicion": f"{suspicious_hops} of {hops} hops at or above suspicion threshold {settings.suspicion_threshold}",
        "corroboration": f"{len(sources)} independent source system(s): {', '.join(sorted(sources))}",
        "evidence_quality": f"{observed} of {hops} hops directly observed; {hops - observed} inferred via IP resolution",
        "path_length": f"{hops} hop(s)",
        "recency": f"last step at {_fmt(last_t)}; dataset ends {_fmt(g.max_time)}",
    }
    ranked = score(components, settings.weights, notes)
    span = last_t - first_t
    reasons = [
        f"Reaches {target.type.value} {target.name} (criticality {target.criticality}/5) in {hops} hop(s).",
        f"Temporally consistent: each step follows the one that enables it; whole chain spans {_span(span)} "
        f"({_fmt(first_t)} -> {_fmt(last_t)}).",
    ]
    if suspicious_hops:
        reasons.append(f"{suspicious_hops} of {hops} hop(s) carry alert-linked or high-severity evidence.")
    else:
        reasons.append("No hop carries suspicious evidence: this is reachability consistent with normal use, not an indicator of attack.")
    reasons.append(notes["corroboration"][0].upper() + notes["corroboration"][1:] + ".")
    if observed < hops:
        reasons.append(f"{hops - observed} hop(s) rely on IP-to-host resolution from the asset inventory (inferred).")
    return {
        "nodes": [rels[0].source] + [r.target for r in rels],
        "hops": hops, "steps": steps, "start": first_t.isoformat(), "end": last_t.isoformat(),
        "target": target.id, "suspicious_hops": suspicious_hops, "sources": sorted(sources),
        "temporally_consistent": True, "reasons": reasons, **ranked,
    }


def _span(td: timedelta) -> str:
    mins = int(td.total_seconds() // 60)
    return f"{mins // 60} h {mins % 60} min" if mins >= 60 else f"{mins} min"


def _structural_shortest(g: TemporalGraph, q: PathQuery, target: str, settings: AnalysisSettings) -> dict | None:
    allowed = q.rel_types or TRAVERSABLE
    sub = nx.subgraph_view(g.g, filter_edge=lambda u, v, k: RelType(k) in allowed)
    try:
        nodes = nx.shortest_path(sub, q.source, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
    w = Window.from_settings(settings)
    options = [[r for r in (g.rels[d["rel_id"]] for d in g.g.get_edge_data(u, v).values()) if r.type in allowed]
               for u, v in zip(nodes, nodes[1:])]
    best_reason = None
    combos: list[list[Relationship]] = [[]]
    for opts in options:
        combos = [c + [o] for c in combos for o in opts][:64]
    for rels in combos:
        chosen, reason = schedule(g, rels, q.since, w)
        if chosen is not None:
            return {"nodes": nodes, "hops": len(nodes) - 1, "relationships": [r.id for r in rels],
                    "temporally_consistent": True, "reason": None}
        best_reason = best_reason or reason
    return {"nodes": nodes, "hops": len(nodes) - 1, "relationships": [r.id for r in combos[0]],
            "temporally_consistent": False, "reason": best_reason}


def find_paths(g: TemporalGraph, q: PathQuery, settings: AnalysisSettings,
               candidate_provider: CandidateProvider | None = None) -> dict:
    if q.source not in g.entities:
        raise PathError(f"unknown source entity {q.source!r}")
    if not 1 <= q.max_hops <= HARD_MAX_HOPS:
        raise PathError(f"max_hops must be between 1 and {HARD_MAX_HOPS}")
    targets = q.targets or default_targets(g, q.source)
    unknown = [t for t in targets if t not in g.entities]
    if unknown:
        raise PathError(f"unknown target entity {unknown[0]!r}")
    if q.source in targets:
        targets = [t for t in targets if t != q.source]
    st = _Search()
    w = Window.from_settings(settings)
    engine = "local temporal DFS (NetworkX)"
    if candidate_provider is None:
        _dfs(g, q, set(targets), st, settings)
    else:
        engine = "Neo4j candidates + temporal validation"
        allowed = q.rel_types or TRAVERSABLE
        for t in targets:
            for rel_ids in candidate_provider(q.source, t, q.max_hops):
                rels = [g.rels[r] for r in rel_ids if r in g.rels]
                if len(rels) != len(rel_ids) or any(r.type not in allowed for r in rels):
                    continue
                st.expansions += 1
                chosen, reason = schedule(g, rels, q.since, w)
                if chosen is not None:
                    st.candidates.append(rel_ids)
                elif len(st.rejected) < MAX_REJECTED:
                    st.rejected.append({"nodes": [q.source] + [r.target for r in rels], "relationships": rel_ids,
                                        "reason": reason})
    explained = [p for p in (_explain_path(g, c, q, settings) for c in st.candidates) if p]
    explained.sort(key=lambda p: (-p["score"], p["hops"], p["nodes"]))
    seen: set[tuple] = set()
    unique = []
    for p in explained:
        sig = tuple(g.entities[n].attributes.get("image", n) if g.entities[n].type == EntityType.PROCESS else n for n in p["nodes"])
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(p)
    shortest = _structural_shortest(g, q, targets[0], settings) if len(targets) == 1 else None
    return {
        "source": q.source, "targets": targets, "max_hops": q.max_hops,
        "since": q.since.isoformat() if q.since else None,
        "window": {"clock_skew_seconds": settings.clock_skew_seconds, "max_hop_gap_hours": settings.max_hop_gap_hours},
        "paths": unique[: q.max_paths],
        "total_valid_paths": len(unique),
        "rejected_temporally_impossible": st.rejected,
        "structural_shortest_path": shortest,
        "search": {"engine": engine, "expansions": st.expansions, "truncated": st.truncated,
                   "budget": settings.search_budget, "candidate_cap": MAX_CANDIDATES},
    }
