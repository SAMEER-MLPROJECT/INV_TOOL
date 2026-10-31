from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .config import AnalysisSettings
from .graph.builder import GraphView, TemporalGraph
from .graph.paths import PathQuery, find_paths
from .models import EntityType, NormalizedEvent
from .narrative import describe_event
from .risk import corroboration_factor, priority_label, recency_factor, score
from .rules import DISMISSED_DISPOSITIONS

MAX_SUPPORTING_EVENTS = 250
HUB_MIN_NEIGHBOURS = 20
HUB_MEDIAN_FACTOR = 4


def hub_entities(g: TemporalGraph) -> set[str]:
    infra = {EntityType.USER, EntityType.HOST, EntityType.DATABASE, EntityType.SERVICE}
    counts = {}
    for n in g.g.nodes:
        if g.entities[n].type not in infra:
            continue
        nbrs = {v for v in g.g.successors(n)} | {u for u in g.g.predecessors(n)}
        nbrs = {x for x in nbrs if g.entities[x].type in infra}
        if nbrs:
            counts[n] = len(nbrs)
    if not counts:
        return set()
    ordered = sorted(counts.values())
    median = ordered[len(ordered) // 2]
    limit = max(HUB_MIN_NEIGHBOURS, HUB_MEDIAN_FACTOR * median)
    return {n for n, c in counts.items() if c >= limit}


class _UF:
    def __init__(self, items: list[str]) -> None:
        self.p = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if ra > rb:
            ra, rb = rb, ra
        self.p[rb] = ra
        return True


def _seed_entities(g: TemporalGraph, ev: NormalizedEvent) -> set[str]:
    ents: set[str] = set()
    if ev.category == "alert":
        ents.update(e for e in ev.alert_entities if e in g.entities)
        for ref in ev.related_event_ids:
            for uid in ([ref] if ref in g.events else g.by_event_id.get(ref, [])):
                ents.update(x for x in g.event_elements.get(uid, ()) if x in g.entities)
    else:
        ents.update(x for x in g.event_elements.get(ev.uid, ()) if x in g.entities)
    for e in list(ents):
        ent = g.entities[e]
        if ent.type == EntityType.PROCESS and ent.attributes.get("host"):
            ents.add(f"host:{ent.attributes['host']}")
    return {e for e in ents if g.entities[e].type != EntityType.ALERT}


def correlate(g: TemporalGraph, settings: AnalysisSettings, statuses: dict[str, str] | None = None) -> list[dict]:
    window = timedelta(minutes=settings.correlation_window_minutes)
    seeds = [ev for ev in g.events.values()
             if ev.category == "alert" or ev.severity >= settings.suspicion_threshold]
    seeds.sort(key=lambda e: (e.timestamp, e.uid))
    if not seeds:
        return []
    ents = {s.uid: _seed_entities(g, s) for s in seeds}
    hubs = hub_entities(g)
    uf = _UF([s.uid for s in seeds])
    links: list[dict] = []
    view = GraphView(g)

    for s in seeds:
        if s.category != "alert":
            continue
        for ref in s.related_event_ids:
            for other in seeds:
                if other.uid != s.uid and (other.uid == ref or other.event_id == ref) and uf.union(s.uid, other.uid):
                    links.append({"rule": "R-COR-03", "a": s.uid, "b": other.uid, "detail": f"{s.event_id} cites {ref}"})

    for i, a in enumerate(seeds):
        ea = ents[a.uid] - hubs
        for b in seeds[i + 1:]:
            gap = b.timestamp - a.timestamp
            if gap > window:
                break
            eb = ents[b.uid] - hubs
            shared = sorted(ea & eb)
            if shared:
                if uf.union(a.uid, b.uid):
                    links.append({"rule": "R-COR-01", "a": a.uid, "b": b.uid,
                                  "detail": f"share {', '.join(shared[:3])}; {int(gap.total_seconds() // 60)} min apart"})
                continue
            lo, hi = a.timestamp - window, b.timestamp + window
            hit = None
            for x in ea:
                for rel in view.out_rels(x) + view.in_rels(x):
                    other = rel.target if rel.source == x else rel.source
                    if other in eb and any(lo <= o.timestamp <= hi for o in rel.occurrences):
                        hit = rel
                        break
                if hit:
                    break
            if hit is not None and uf.union(a.uid, b.uid):
                links.append({"rule": "R-COR-02", "a": a.uid, "b": b.uid,
                              "detail": f"{hit.source} -{hit.type.value}-> {hit.target} within window"})

    groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for s in seeds:
        groups[uf.find(s.uid)].append(s)

    incidents = []
    for members in groups.values():
        incidents.append(_build_incident(g, members, links, ents, window, settings, statuses or {}))
    incidents.sort(key=lambda x: x["start"])
    for n, inc in enumerate(incidents, start=1):
        inc["id"] = f"INC-{n:04d}"
    incidents.sort(key=lambda x: (-x["score"], x["start"]))
    return incidents


def _build_incident(g: TemporalGraph, members: list[NormalizedEvent], links: list[dict], ents: dict[str, set[str]],
                    window: timedelta, settings: AnalysisSettings, statuses: dict[str, str]) -> dict:
    member_ids = {m.uid for m in members}
    entity_ids: set[str] = set()
    for m in members:
        entity_ids |= ents[m.uid]
    start, end = members[0].timestamp, members[-1].timestamp

    support: set[str] = set(member_ids)
    for m in members:
        for ref in m.related_event_ids:
            support.update([ref] if ref in g.events else g.by_event_id.get(ref, []))
    lo, hi = start - window, end + window
    for rel in g.rels.values():
        if rel.source in entity_ids and rel.target in entity_ids:
            for o in rel.occurrences:
                if lo <= o.timestamp <= hi and o.suspicion > 0:
                    support.add(o.event_uid)
    support_events = sorted((g.events[u] for u in support if u in g.events), key=lambda e: (e.timestamp, e.uid))
    support_events = support_events[:MAX_SUPPORTING_EVENTS]

    alerts = [m for m in members if m.category == "alert"]
    active = [m for m in members if (m.disposition or "") not in DISMISSED_DISPOSITIONS]
    dismissed_only = not active
    sevs = [m.severity for m in (active or members)]
    sources = sorted({e.source_system for e in support_events})
    grouped: dict[str, list[str]] = defaultdict(list)
    for e in sorted(entity_ids):
        grouped[g.entities[e].type.value].append(e)
    max_crit = max((g.entities[e].criticality for e in entity_ids), default=1)

    hypothesis = None
    start_entity = None
    for m in members:
        for pref in (EntityType.USER, EntityType.HOST):
            cand = sorted(e for e in ents[m.uid] if g.entities[e].type == pref)
            if cand:
                start_entity = cand[0]
                break
        if start_entity:
            break
    if start_entity:
        res = find_paths(g, PathQuery(source=start_entity, max_hops=settings.default_max_hops, max_paths=3,
                                      since=start - window), settings)
        if res["paths"]:
            top = res["paths"][0]
            hypothesis = {"source": start_entity, "target": top["target"], "nodes": top["nodes"],
                          "score": top["score"], "priority": top["priority"], "steps": top["steps"],
                          "reasons": top["reasons"]}
            max_crit = max(max_crit, g.entities[top["target"]].criticality)

    explicit = sum(1 for m in members if m.related_event_ids or m.category != "alert")
    components = {
        "criticality": max_crit / 5.0,
        "suspicion": 0.6 * max(sevs) + 0.4 * (sum(sevs) / len(sevs)),
        "corroboration": corroboration_factor(len(sources)),
        "evidence_quality": explicit / len(members),
        "path_length": 1.0 if hypothesis and any(s["suspicion"] >= settings.suspicion_threshold for s in hypothesis["steps"])
        else (0.5 if hypothesis else 0.0),
        "recency": recency_factor(end, g.max_time, settings.recency_half_life_hours),
    }
    notes = {
        "criticality": f"most critical involved or reachable asset: {max_crit}/5",
        "suspicion": f"max seed severity {max(sevs):.2f}, mean {sum(sevs) / len(sevs):.2f}",
        "corroboration": f"{len(sources)} independent source system(s): {', '.join(sources)}",
        "evidence_quality": f"{explicit} of {len(members)} seed signal(s) cite concrete evidence records",
        "path_length": "attack-path hypothesis contains suspicious hops" if components["path_length"] == 1.0
        else ("a benign-looking path to a critical asset exists" if hypothesis else "no path to a critical asset"),
        "recency": f"last signal {end.strftime('%Y-%m-%d %H:%M')}Z",
    }
    ranked = score(components, settings.weights, notes)
    if dismissed_only:
        ranked["score"] = round(ranked["score"] * 0.3, 1)
        ranked["priority"] = priority_label(ranked["score"])
    inc_links = [l for l in links if l["a"] in member_ids and l["b"] in member_ids]
    title_alert = max(alerts, key=lambda a: a.severity) if alerts else members[0]
    title = title_alert.alert_name or describe_event(title_alert)
    explanation = [
        f"{len(members)} seed signal(s) between {start.strftime('%Y-%m-%d %H:%M')}Z and {end.strftime('%H:%M')}Z "
        f"were grouped by {len(inc_links)} correlation link(s).",
        f"Evidence comes from {len(sources)} independent source system(s): {', '.join(sources)}.",
    ]
    if dismissed_only:
        explanation.append("Every seed alert was dispositioned benign/false-positive by its source; priority reduced (x0.3).")
    if hypothesis:
        explanation.append(f"Attack-path hypothesis: {' -> '.join(hypothesis['nodes'])}.")
    return {
        "id": "", "title": title, "start": start.isoformat(), "end": end.isoformat(),
        "seed_events": [m.uid for m in members],
        "alerts": [{"uid": a.uid, "rule": a.alert_name, "technique": a.technique, "severity": a.severity,
                    "disposition": a.disposition, "timestamp": a.timestamp.isoformat()} for a in alerts],
        "entities": dict(grouped), "affected_assets": [e for e in sorted(entity_ids) if g.entities[e].type in
                                                        (EntityType.HOST, EntityType.DATABASE, EntityType.SERVICE)],
        "identities": grouped.get("user", []), "supporting_events": [e.uid for e in support_events],
        "evidence_sources": sources, "independent_sources": len(sources),
        "correlation_links": inc_links, "explanation": explanation,
        "timeline": [{"uid": e.uid, "timestamp": e.timestamp.isoformat(), "source_system": e.source_system,
                      "category": e.category, "severity": e.severity, "seed": e.uid in member_ids,
                      "description": describe_event(e)} for e in support_events],
        "hypothesis": hypothesis, "dismissed_by_source": dismissed_only,
        "analyst_confirmed": [e for e in entity_ids if statuses.get(e) == "confirmed"],
        **ranked,
    }
