from __future__ import annotations

from datetime import datetime, timedelta

import networkx as nx

from .config import AnalysisSettings
from .graph.blast import compute_blast_radius
from .graph.builder import TemporalGraph
from .graph.paths import PathQuery, default_targets, find_paths
from .models import EntityType, Relationship

MAX_ACTIONS = 5
PLAN_PATHS = 60

COST = {
    ("host", "workstation"): 1.0, ("host", "server"): 3.0, ("host", "domain_controller"): 5.0,
    ("host", "network_device"): 4.0, ("host", ""): 1.5, ("host", "unmanaged"): 0.5,
    ("user", "user"): 1.0, ("user", "service_account"): 2.0, ("user", "admin_account"): 2.0, ("user", ""): 1.0,
    ("process", "process"): 0.3, ("service", "service"): 0.5, ("ip", "external"): 0.3, ("ip", "internal_unmanaged"): 0.5,
    ("domain", "domain"): 0.3,
}
VERB = {"host": "Isolate host", "user": "Disable / reset credentials of", "process": "Terminate process",
        "service": "Remove service", "ip": "Block address", "domain": "Sinkhole domain"}
EDGE_COST = 0.8
HOLDABLE = {"user", "host", "process", "service"}


class WhatIfError(ValueError):
    pass


def action_for(g: TemporalGraph, target: str) -> dict:
    if "|" in target:
        rel = g.rels.get(target)
        if rel is None:
            raise WhatIfError(f"unknown relationship {target!r}")
        port = next((o.attributes.get("dst_port") for o in rel.occurrences if o.attributes.get("dst_port")), None)
        label = f"Block {rel.type.value} {rel.source.split(':', 1)[1]} → {rel.target.split(':', 1)[1]}" + (f" (port {port})" if port else "")
        return {"kind": "block_relationship", "target": target, "label": label, "cost": EDGE_COST}
    ent = g.entities.get(target)
    if ent is None:
        raise WhatIfError(f"unknown entity {target!r}")
    if ent.type in (EntityType.DATABASE, EntityType.ALERT):
        raise WhatIfError("databases and alerts are protected assets / context, not containment targets")
    cost = COST.get((ent.type.value, ent.category), COST.get((ent.type.value, ""), 1.0))
    return {"kind": f"contain_{ent.type.value}", "target": target, "label": f"{VERB.get(ent.type.value, 'Contain')} {ent.name}",
            "cost": cost}


def counterfactual(g: TemporalGraph, targets: list[str], at: datetime | None) -> TemporalGraph:
    nodes = {t for t in targets if "|" not in t}
    edges = {t for t in targets if "|" in t}
    for n in list(nodes):
        ent = g.entities.get(n)
        if ent is not None and ent.type == EntityType.HOST:
            nodes |= {e.id for e in g.entities.values() if e.type == EntityType.PROCESS and e.attributes.get("host") == ent.name}
    cf = TemporalGraph()
    cf.entities, cf.events, cf.event_elements, cf.entity_events = g.entities, g.events, g.event_elements, g.entity_events
    cf.ip_to_host, cf.by_event_id, cf.min_time, cf.max_time = g.ip_to_host, g.by_event_id, g.min_time, g.max_time
    cf.deviation_models = g.deviation_models
    cf.g = nx.MultiDiGraph()
    cf.g.add_nodes_from(g.g.nodes)
    for rid, rel in g.rels.items():
        hit = rid in edges or rel.source in nodes or rel.target in nodes
        occs = [o for o in rel.occurrences if not hit or (at is not None and o.timestamp < at)]
        if not occs:
            continue
        new = rel if len(occs) == len(rel.occurrences) else Relationship(id=rel.id, source=rel.source, target=rel.target,
                                                                         type=rel.type, occurrences=occs)
        cf.rels[rid] = new
        cf._times[rid] = [o.timestamp for o in occs]
        cf.g.add_edge(rel.source, rel.target, key=rel.type.value, rel_id=rid)
    return cf


def footholds(g: TemporalGraph, source: str, at: datetime | None, settings: AnalysisSettings, hops: int) -> list[dict]:
    if at is None:
        return [{"id": source, "since": None}]
    since = at - timedelta(minutes=settings.correlation_window_minutes)
    blast = compute_blast_radius(g, source, settings, max_hops=hops, temporal=True, since=since)
    held = [{"id": source, "since": None}]
    for n in blast["nodes"]:
        arr = n["earliest_arrival"]
        if (n["classification"] == "SUSPECTED_LATERAL_MOVEMENT" and arr and datetime.fromisoformat(arr) < at
                and n["type"] in HOLDABLE):
            held.append({"id": n["id"], "since": arr})
    return held


def _metrics(g: TemporalGraph, held: list[dict], targets: list[str] | None, at: datetime | None,
             settings: AnalysisSettings, hops: int) -> dict:
    held_ids = {h["id"] for h in held}
    paths: dict[tuple, dict] = {}
    reached: dict[str, dict] = {}
    for h in held:
        f = h["id"]
        if f not in g.entities:
            continue
        tg = [t for t in (targets or default_targets(g, f)) if t not in held_ids]
        if tg:
            res = find_paths(g, PathQuery(source=f, targets=tg, max_hops=hops, max_paths=PLAN_PATHS, since=at), settings)
            for p in res["paths"]:
                paths.setdefault(tuple(p["nodes"]), p)
        blast = compute_blast_radius(g, f, settings, max_hops=hops, temporal=at is not None, since=at)
        for n in blast["nodes"]:
            if n["id"] in held_ids:
                continue
            prev = reached.get(n["id"])
            if prev is None or (prev["classification"] != "SUSPECTED_LATERAL_MOVEMENT"
                                and n["classification"] == "SUSPECTED_LATERAL_MOVEMENT"):
                reached[n["id"]] = n
    plist = sorted(paths.values(), key=lambda p: -p["score"])
    crit = [n for n in reached.values() if n["criticality"] >= 4]
    return {
        "valid_paths": len(plist),
        "critical_paths": sum(1 for p in plist if p["priority"] in ("Critical", "High")),
        "reachable": len(reached),
        "suspected": sum(1 for n in reached.values() if n["classification"] == "SUSPECTED_LATERAL_MOVEMENT"),
        "critical_assets_reachable": sorted(n["id"] for n in crit),
        "crown_jewels_suspected": sorted(n["id"] for n in crit if n["classification"] == "SUSPECTED_LATERAL_MOVEMENT"),
        "_paths": plist,
    }


def _public(m: dict) -> dict:
    return {k: v for k, v in m.items() if not k.startswith("_")}


def what_if(g: TemporalGraph, source: str, actions: list[str], at: datetime | None, settings: AnalysisSettings,
            hops: int = 5, targets: list[str] | None = None) -> dict:
    if source not in g.entities:
        raise WhatIfError(f"unknown source {source!r}")
    acts = [action_for(g, a) for a in actions]
    held = footholds(g, source, at, settings, hops)
    before = _metrics(g, held, targets, at, settings, hops)
    after = _metrics(counterfactual(g, actions, at), held, targets, at, settings, hops)
    return {"source": source, "at": at.isoformat() if at else None, "actions": acts, "footholds": held,
            "before": _public(before), "after": _public(after),
            "prevented": sorted(set(before["critical_assets_reachable"]) - set(after["critical_assets_reachable"])),
            "remaining_paths": [p["nodes"] for p in after["_paths"][:5]]}


def _risk(m: dict) -> float:
    return sum(p["score"] for p in m["_paths"])


def _contained(m: dict) -> bool:
    return m["critical_paths"] == 0 and not m["crown_jewels_suspected"]


def plan_containment(g: TemporalGraph, source: str, at: datetime | None, settings: AnalysisSettings, hops: int = 5,
                     targets: list[str] | None = None) -> dict:
    if source not in g.entities:
        raise WhatIfError(f"unknown source {source!r}")
    held = footholds(g, source, at, settings, hops)
    baseline = _metrics(g, held, targets, at, settings, hops)
    chosen: list[str] = []
    rounds = []
    current = baseline
    candidates_table: list[dict] = []
    while not _contained(current) and len(chosen) < MAX_ACTIONS:
        cands: list[str] = []
        for h in held:
            if h["id"] not in cands:
                cands.append(h["id"])
        for p in current["_paths"]:
            for n in p["nodes"][:-1]:
                if n not in cands:
                    cands.append(n)
            for st in p["steps"]:
                if st["relationship_id"] not in cands:
                    cands.append(st["relationship_id"])
        base_risk = _risk(current)
        scored = []
        for cand in cands:
            if cand in chosen:
                continue
            try:
                act = action_for(g, cand)
            except WhatIfError:
                continue
            ent = g.entities.get(cand)
            if ent is not None and ent.type == EntityType.PROCESS and at is not None and ent.first_seen and ent.first_seen > at:
                continue
            m = _metrics(counterfactual(g, chosen + [cand], at), held, targets, at, settings, hops)
            reduction = base_risk - _risk(m)
            if reduction <= 0:
                continue
            scored.append({"value": reduction / act["cost"], "reduction": reduction, "action": act, "metrics": m})
        if not scored:
            break
        scored.sort(key=lambda x: (-x["value"], x["action"]["cost"], x["action"]["target"]))
        finishing = [c for c in scored if _contained(c["metrics"])]
        if not candidates_table:
            candidates_table = [{**c["action"], "risk_reduction_pct": round(100 * c["reduction"] / base_risk, 1) if base_risk else 0.0,
                                 "value_per_cost": round(c["value"], 1),
                                 "crown_jewels_protected": sorted(set(current["crown_jewels_suspected"]) - set(c["metrics"]["crown_jewels_suspected"])),
                                 "after": _public(c["metrics"])} for c in scored[:10]]
        best = min(finishing, key=lambda c: (c["action"]["cost"], -c["reduction"])) if finishing else scored[0]
        chosen.append(best["action"]["target"])
        current = best["metrics"]
        first_risk = _risk(baseline)
        rounds.append({"action": best["action"], "risk_reduction_pct": round(100 * (first_risk - _risk(current)) / first_risk, 1) if first_risk else 0.0,
                       "after": _public(current)})
    pruned: list[str] = []
    if _contained(current) and len(chosen) > 1:
        for a in list(chosen):
            rest = [x for x in chosen if x != a]
            m = _metrics(counterfactual(g, rest, at), held, targets, at, settings, hops)
            if _contained(m):
                chosen = rest
                current = m
                pruned.append(a)
        if pruned:
            rounds = [r for r in rounds if r["action"]["target"] not in pruned]
            base_risk = _risk(baseline)
            acc: list[str] = []
            for r in rounds:
                acc.append(r["action"]["target"])
                m = _metrics(counterfactual(g, acc, at), held, targets, at, settings, hops)
                r["after"] = _public(m)
                r["risk_reduction_pct"] = round(100 * (base_risk - _risk(m)) / base_risk, 1) if base_risk else 0.0
    return {
        "source": source, "effective_at": at.isoformat() if at else None, "footholds": held,
        "pruned_as_redundant": [action_for(g, a)["label"] for a in pruned],
        "before": _public(baseline), "plan": rounds, "after": _public(current),
        "contained": _contained(current),
        "residual_paths": [p["nodes"] for p in current["_paths"][:5]],
        "candidates": candidates_table,
        "method": "each round simulates every candidate action on the counterfactual graph and keeps the one with the largest "
                  "reduction of residual path risk per unit of disruption cost (greedy, verified)",
        "caveat": "Recommendations reflect observed evidence only; weigh the listed disruption cost against business impact.",
    }
