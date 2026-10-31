"""Blast-radius engine.

Answers: "if this entity is compromised, what could the adversary reach, how quickly, and
on what evidence?" Reachability is computed with a hop-bounded label-correcting search.
In temporal mode a node only counts as reached if a time-respecting route exists from the
chosen start time (earliest-arrival semantics, see methodology).

Reachability never proves compromise. Every reached node is classified into one of four
explicitly different evidence tiers.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from ..config import AnalysisSettings
from ..models import EntityType, RelType
from .builder import GraphView, TemporalGraph

HARD_MAX_HOPS = 8

CONFIRMED = "CONFIRMED_COMPROMISE"
SUSPECTED = "SUSPECTED_LATERAL_MOVEMENT"
OBSERVED = "OBSERVED_CONNECTION"
POTENTIAL = "POTENTIAL_EXPOSURE"

CLASS_ORDER = {CONFIRMED: 0, SUSPECTED: 1, OBSERVED: 2, POTENTIAL: 3}
CLASS_DEFINITIONS = {
    CONFIRMED: "An analyst has explicitly marked this entity as compromised. Never assigned automatically.",
    SUSPECTED: "Reached through an unbroken chain of interactions, starting at the selected entity, whose evidence "
               "is at or above the suspicion threshold (alert-linked or high-severity source records).",
    OBSERVED: "Directly connected to the selected entity by observed activity with no suspicious evidence.",
    POTENTIAL: "Reachable through two or more hops of ordinary activity. Exposure, not evidence of compromise.",
}


class BlastError(ValueError):
    pass


def first_suspicious_time(g: TemporalGraph, entity: str, threshold: float) -> datetime | None:
    """Earliest suspicious occurrence touching ``entity`` (in either direction)."""
    best: datetime | None = None
    view = GraphView(g)
    for rel in view.out_rels(entity) + view.in_rels(entity):
        for occ in rel.occurrences:
            if occ.suspicion >= threshold:
                if best is None or occ.timestamp < best:
                    best = occ.timestamp
                break
    return best


def compute_blast_radius(
    g: TemporalGraph,
    source: str,
    settings: AnalysisSettings,
    max_hops: int = 3,
    temporal: bool = True,
    since: datetime | None = None,
    rel_types: set[RelType] | None = None,
    include_processes: bool = True,
    statuses: dict[str, str] | None = None,
) -> dict:
    if source not in g.entities:
        raise BlastError(f"unknown entity {source!r}")
    if not 1 <= max_hops <= HARD_MAX_HOPS:
        raise BlastError(f"hops must be between 1 and {HARD_MAX_HOPS}")
    statuses = statuses or {}
    view = GraphView(g)
    skew = timedelta(seconds=settings.clock_skew_seconds)
    start_time = since
    if temporal and start_time is None:
        start_time = first_suspicious_time(g, source, settings.suspicion_threshold)

    # label-correcting search bounded by hops: arrival[v] = earliest feasible arrival
    arrival: dict[str, datetime | None] = {source: start_time if temporal else None}
    hop: dict[str, int] = {source: 0}
    pred: dict[str, str] = {}
    susp_edges: list[tuple[str, str, str]] = []  # (u, v, rel id) with suspicious evidence after arrival at u
    frontier = {source}
    for h in range(1, HARD_MAX_HOPS + 1):
        nxt: set[str] = set()
        for u in frontier:
            t_u = arrival[u] if temporal else None
            for rel in view.out_rels(u, rel_types):
                v = rel.target
                if v == source:
                    continue
                idx = view.earliest_after(rel, t_u, skew) if temporal else 0
                if idx is None:
                    continue
                occ_t = rel.occurrences[idx].timestamp
                t_v = (occ_t if t_u is None or occ_t > t_u else t_u) if temporal else None
                window = rel.occurrences[idx:] if temporal else rel.occurrences
                if any(o.suspicion >= settings.suspicion_threshold for o in window):
                    susp_edges.append((u, v, rel.id))
                better_time = temporal and v in arrival and arrival[v] is not None and t_v is not None and t_v < arrival[v]
                if v not in hop:
                    hop[v], arrival[v], pred[v] = h, t_v, rel.id
                    nxt.add(v)
                elif better_time:
                    arrival[v] = t_v  # earlier arrival can unlock more continuations; keep first hop distance
                    nxt.add(v)
        frontier = nxt
        if not frontier:
            break

    # SUSPECTED requires an unbroken chain of suspicious hops from the selected entity: a node
    # reached through ordinary activity is not "suspected" merely because someone else later
    # used one of its outgoing connections maliciously.
    suspicious_in: dict[str, list[str]] = {}
    changed = True
    while changed:
        changed = False
        for u, v, rid in susp_edges:
            if (u == source or u in suspicious_in) and hop.get(v, 99) <= max_hops and v != source:
                lst = suspicious_in.setdefault(v, [])
                if rid not in lst:
                    lst.append(rid)
                    changed = True

    def chain(v: str) -> list[str]:
        out = []
        while v in pred:
            out.append(pred[v])
            v = g.rels[pred[v]].source
        return list(reversed(out))

    growth = Counter(h for n, h in hop.items() if n != source)
    nodes = []
    for v, h in hop.items():
        if v == source or h > max_hops:
            continue
        ent = g.entities[v]
        if not include_processes and ent.type == EntityType.PROCESS:
            continue
        if statuses.get(v) == "confirmed":
            cls = CONFIRMED
        elif v in suspicious_in:
            cls = SUSPECTED
        elif h == 1:
            cls = OBSERVED
        else:
            cls = POTENTIAL
        susp = 1.0 if cls in (CONFIRMED, SUSPECTED) else 0.0
        impact = round(100 * (0.6 * ent.criticality / 5 + 0.25 / h + 0.15 * susp), 1)
        path = chain(v)
        nodes.append({
            "id": v, "type": ent.type.value, "name": ent.name, "category": ent.category,
            "criticality": ent.criticality, "hop": h,
            "earliest_arrival": arrival[v].isoformat() if temporal and arrival.get(v) else None,
            "classification": cls, "impact": impact, "via": path,
            "suspicious_relationships": suspicious_in.get(v, []),
            "analyst_status": statuses.get(v),
        })
    nodes.sort(key=lambda n: (CLASS_ORDER[n["classification"]], -n["impact"], n["hop"], n["id"]))
    by_class = Counter(n["classification"] for n in nodes)
    by_type = Counter(n["type"] for n in nodes)
    critical = [n for n in nodes if n["criticality"] >= 4]
    accounts = [n for n in nodes if n["type"] == EntityType.USER.value]
    cumulative, running = [], 0
    for h in range(1, HARD_MAX_HOPS + 1):
        running += growth.get(h, 0)
        cumulative.append({"hops": h, "reachable": running})
    edge_ids = sorted({r for n in nodes for r in n["via"]})
    return {
        "source": source, "max_hops": max_hops, "temporal": temporal,
        "start_time": start_time.isoformat() if start_time else None,
        "start_time_basis": ("explicit" if since else "first suspicious activity on the entity") if temporal and start_time
        else ("no suspicious activity found; all observed history considered" if temporal else "time ignored (structural reachability)"),
        "nodes": nodes,
        "edges": edge_ids,
        "summary": {
            "reachable": len(nodes), "by_classification": dict(by_class), "by_type": dict(by_type),
            "critical_assets": [{"id": n["id"], "name": n["name"], "criticality": n["criticality"], "hop": n["hop"],
                                 "classification": n["classification"]} for n in critical],
            "accounts": [n["id"] for n in accounts],
        },
        "growth": cumulative,
        "class_definitions": CLASS_DEFINITIONS,
    }
