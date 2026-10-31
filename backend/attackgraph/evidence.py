from __future__ import annotations

from datetime import datetime, timezone

from .graph.builder import GraphView, TemporalGraph
from .models import Basis, NormalizedEvent, RelType
from .narrative import describe_event
from .rules import RULES

HASH_LIMITATION = (
    "SHA-256 digests prove that a file is byte-identical to the file that was hashed at ingestion or export time. "
    "They do not independently prove that the original evidence is authentic, complete, or untampered before it "
    "reached AttackGraph Lens."
)

BASIS_TEXT = {
    Basis.OBSERVED: "Directly observed: both endpoints are named explicitly in the source record.",
    Basis.INFERRED: "Inferred: at least one endpoint was resolved from an IP address via the asset inventory (rule R-RES-01).",
}


def event_dict(ev: NormalizedEvent, with_raw: bool = False) -> dict:
    d = {
        "uid": ev.uid, "event_id": ev.event_id, "timestamp": ev.timestamp.isoformat(),
        "source_system": ev.source_system, "source_file": ev.source_file, "source_row": ev.source_row,
        "category": ev.category, "action": ev.action, "outcome": ev.outcome, "severity": ev.severity,
        "description": describe_event(ev), "notes": ev.notes,
    }
    if with_raw:
        d["raw"] = ev.raw
        d["normalized"] = ev.model_dump(mode="json", exclude={"raw"})
    return d


def explain_relationship(g: TemporalGraph, rel_id: str, max_occurrences: int = 200) -> dict | None:
    rel = g.rels.get(rel_id)
    if rel is None:
        return None
    rules = sorted({o.rule for o in rel.occurrences} | {o.attributes.get("suspicion_rule") for o in rel.occurrences} - {None})
    occs = []
    for o in rel.occurrences[:max_occurrences]:
        ev = g.events.get(o.event_uid)
        occs.append({
            "event_uid": o.event_uid, "timestamp": o.timestamp.isoformat(), "source_system": o.source_system,
            "source_file": ev.source_file if ev else None, "source_row": ev.source_row if ev else None,
            "basis": o.basis.value, "rule": o.rule, "suspicion": round(o.suspicion, 3),
            "suspicion_rule": o.attributes.get("suspicion_rule") or ("R-SUSP-00" if o.suspicion > 0 else None),
            "alert": o.attributes.get("alert"), "deviation": o.attributes.get("deviation"),
            "attributes": {k: v for k, v in o.attributes.items() if k not in {"alert", "suspicion_rule", "deviation"}},
            "description": describe_event(ev) if ev else "",
        })
    return {
        "id": rel.id, "source": rel.source, "target": rel.target, "type": rel.type.value,
        "basis": rel.basis.value, "basis_explanation": BASIS_TEXT[rel.basis],
        "first_seen": rel.first_seen.isoformat(), "last_seen": rel.last_seen.isoformat(),
        "occurrence_count": len(rel.occurrences), "sources": sorted(rel.sources),
        "independent_sources": len(rel.sources), "max_suspicion": round(rel.max_suspicion, 3),
        "rules": [{"id": r, **RULES.get(r, {"title": r, "description": ""})} for r in rules],
        "occurrences": occs, "truncated": len(rel.occurrences) > max_occurrences,
        "caveat": "A relationship records that an interaction happened. It is not, by itself, evidence of compromise.",
    }


def explain_entity(g: TemporalGraph, entity_id: str, statuses: dict[str, str], max_events: int = 150) -> dict | None:
    ent = g.entities.get(entity_id)
    if ent is None:
        return None
    view = GraphView(g)
    out_rels = view.out_rels(entity_id)
    in_rels = view.in_rels(entity_id)
    alert_rels = [r for r in (g.rels[d["rel_id"]] for _, _, d in g.g.in_edges(entity_id, data=True))
                  if r.type == RelType.ALERTED_ON]
    events = sorted((g.events[u] for u in g.entity_events.get(entity_id, ()) if u in g.events), key=lambda e: e.timestamp)

    def rel_summary(r):
        return {"id": r.id, "type": r.type.value, "source": r.source, "target": r.target, "count": len(r.occurrences),
                "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
                "max_suspicion": round(r.max_suspicion, 3), "basis": r.basis.value}

    return {
        **ent.model_dump(mode="json"),
        "analyst_status": statuses.get(entity_id),
        "why_it_exists": (f"Listed in the asset inventory ({ent.attributes.get('inventory_ref')})." if ent.in_inventory
                          else f"Referenced by {len(events)} source record(s); not present in the asset inventory."),
        "outbound": [rel_summary(r) for r in sorted(out_rels, key=lambda r: -r.max_suspicion)],
        "inbound": [rel_summary(r) for r in sorted(in_rels, key=lambda r: -r.max_suspicion)],
        "alerts": [{"alert": r.source, "rule": g.entities[r.source].attributes.get("rule"),
                    "severity": g.entities[r.source].attributes.get("severity"),
                    "disposition": g.entities[r.source].attributes.get("disposition"),
                    "timestamp": r.first_seen.isoformat()} for r in alert_rels],
        "event_count": len(events),
        "events": [event_dict(e) for e in events[-max_events:]],
    }


def explain_event(g: TemporalGraph, uid: str) -> dict | None:
    ev = g.events.get(uid)
    if ev is None:
        return None
    elements = sorted(g.event_elements.get(uid, ()))
    citing = [a.uid for a in g.events.values() if a.category == "alert" and (uid in a.related_event_ids or ev.event_id in a.related_event_ids)]
    unresolved = []
    if ev.category == "alert":
        unresolved = [r for r in ev.related_event_ids if r not in g.events and r not in g.by_event_id]
    return {
        **event_dict(ev, with_raw=True),
        "graph_relationships": [e for e in elements if "|" in e],
        "graph_entities": [e for e in elements if "|" not in e],
        "cited_by_alerts": citing,
        "unresolved_evidence_refs": unresolved,
    }


def build_manifest(files: list[dict], exports: list[dict], event_count: int) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "SHA-256",
        "source_files": [{k: f[k] for k in ("file_name", "sha256", "size_bytes", "source_system", "records_read",
                                             "accepted", "rejected", "duplicates", "conflicts", "loaded_at")} for f in files],
        "exports": exports,
        "events_in_graph": event_count,
        "limitation": HASH_LIMITATION,
    }
