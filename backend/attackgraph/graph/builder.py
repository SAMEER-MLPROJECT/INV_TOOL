from __future__ import annotations

import bisect
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

import networkx as nx

from ..ingest.loader import InventoryItem
from ..ingest.normalize import is_ip, is_private_ip
from ..models import TRAVERSABLE, Basis, Entity, EntityType, NormalizedEvent, Occurrence, Relationship, RelType
from ..rules import DISMISSED_DISPOSITIONS

_INVENTORY_TYPES = {
    "workstation": (EntityType.HOST, "workstation"),
    "server": (EntityType.HOST, "server"),
    "domain_controller": (EntityType.HOST, "domain_controller"),
    "network_device": (EntityType.HOST, "network_device"),
    "database": (EntityType.DATABASE, "database"),
    "user": (EntityType.USER, "user"),
    "service_account": (EntityType.USER, "service_account"),
    "admin_account": (EntityType.USER, "admin_account"),
}


def eid(etype: EntityType, name: str) -> str:
    return f"{etype.value}:{name}"


class TemporalGraph:

    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.rels: dict[str, Relationship] = {}
        self.g = nx.MultiDiGraph()
        self.events: dict[str, NormalizedEvent] = {}
        self.event_elements: dict[str, set[str]] = defaultdict(set)
        self.entity_events: dict[str, set[str]] = defaultdict(set)
        self.ip_to_host: dict[str, str] = {}
        self.by_event_id: dict[str, list[str]] = defaultdict(list)
        self._times: dict[str, list[datetime]] = {}
        self.deviation_models: dict = {}
        self.min_time: datetime | None = None
        self.max_time: datetime | None = None

    def entity(self, etype: EntityType, name: str, ts: datetime | None = None, category: str = "") -> Entity:
        key = eid(etype, name)
        ent = self.entities.get(key)
        if ent is None:
            ent = Entity(id=key, type=etype, name=name, category=category, criticality=1)
            self.entities[key] = ent
            self.g.add_node(key)
        elif category and not ent.category:
            ent.category = category
        if ts is not None:
            if ent.first_seen is None or ts < ent.first_seen:
                ent.first_seen = ts
            if ent.last_seen is None or ts > ent.last_seen:
                ent.last_seen = ts
        return ent

    def add_occurrence(self, src: Entity, dst: Entity, rtype: RelType, ev: NormalizedEvent, rule: str,
                       basis: Basis, attributes: dict | None = None) -> Relationship | None:
        if src.id == dst.id:
            return None
        rid = f"{src.id}|{rtype.value}|{dst.id}"
        rel = self.rels.get(rid)
        if rel is None:
            rel = Relationship(id=rid, source=src.id, target=dst.id, type=rtype)
            self.rels[rid] = rel
            self.g.add_edge(src.id, dst.id, key=rtype.value, rel_id=rid)
        rel.occurrences.append(
            Occurrence(event_uid=ev.uid, timestamp=ev.timestamp, source_system=ev.source_system, basis=basis,
                       rule=rule, suspicion=ev.severity, attributes={k: v for k, v in (attributes or {}).items() if v is not None})
        )
        self.event_elements[ev.uid].update({rid, src.id, dst.id})
        self.entity_events[src.id].add(ev.uid)
        self.entity_events[dst.id].add(ev.uid)
        return rel

    def load_inventory(self, items: Iterable[InventoryItem]) -> None:
        for it in items:
            etype, category = _INVENTORY_TYPES[it.asset_type]
            ent = self.entity(etype, it.name, category=category)
            ent.category = category
            ent.criticality = it.criticality
            ent.in_inventory = True
            ent.attributes.update({"asset_id": it.asset_id, "owner": it.owner, "tags": it.tags,
                                   "inventory_ref": f"{it.source_file}#row{it.source_row}"})
            if it.ip:
                ent.attributes["ip"] = it.ip
                if etype in (EntityType.HOST, EntityType.DATABASE):
                    self.ip_to_host[it.ip] = ent.id

    def endpoint(self, value: str | None, ts: datetime) -> tuple[Entity | None, bool]:
        if not value:
            return None, False
        if is_ip(value):
            host_id = self.ip_to_host.get(value)
            if host_id:
                ent = self.entities[host_id]
                self.entity(ent.type, ent.name, ts)
                return ent, True
            cat = "internal_unmanaged" if is_private_ip(value) else "external"
            return self.entity(EntityType.IP, value, ts, cat), False
        ent = self.entity(EntityType.HOST, value, ts)
        if not ent.category:
            ent.category = "unmanaged"
        return ent, False


def _process(g: TemporalGraph, host: str, image: str | None, pid: str | None, ts: datetime, user: str | None,
             cmdline: str | None = None) -> Entity | None:
    if not image:
        return None
    name = f"{host}/{image}" + (f"#{pid}" if pid else "")
    ent = g.entity(EntityType.PROCESS, name, ts, "process")
    ent.attributes.setdefault("image", image)
    ent.attributes.setdefault("host", host)
    if pid:
        ent.attributes.setdefault("pid", pid)
    if user:
        ent.attributes.setdefault("user", user)
    if cmdline:
        ent.attributes.setdefault("command_line", cmdline)
    return ent


def _apply_event(g: TemporalGraph, ev: NormalizedEvent) -> None:
    ts = ev.timestamp
    cat = ev.category
    if cat == "authentication":
        user = g.entity(EntityType.USER, ev.user, ts, "user") if ev.user else None
        dst, dst_inf = g.endpoint(ev.dst_host, ts)
        if ev.outcome != "success" or user is None or dst is None:
            for ent in (user, dst):
                if ent is not None:
                    g.entity_events[ent.id].add(ev.uid)
                    g.event_elements[ev.uid].add(ent.id)
            return
        g.add_occurrence(user, dst, RelType.AUTHENTICATED_TO, ev, "R-AUTH-01",
                         Basis.INFERRED if dst_inf else Basis.OBSERVED, {"logon": ev.action, "user": ev.user})
        src, src_inf = g.endpoint(ev.src_host, ts)
        if src is not None and src.id != dst.id:
            g.add_occurrence(src, dst, RelType.CONNECTED_TO, ev, "R-AUTH-02",
                             Basis.INFERRED if (src_inf or dst_inf) else Basis.OBSERVED,
                             {"via": "remote logon", "logon": ev.action, "user": ev.user})
    elif cat in {"process", "network", "privilege", "service"} and ev.src_host and (cat != "network" or ev.process):
        host, _ = g.endpoint(ev.src_host, ts)
        if host is None:
            return
        cmd = ev.raw.get("cmdline") if isinstance(ev.raw.get("cmdline"), str) else None
        proc = _process(g, host.name, ev.process, ev.process_id, ts, ev.user, cmd if cat == "process" else None)
        if proc is None:
            return
        attrs = {"user": ev.user, "action": ev.action}
        if cat == "process":
            g.add_occurrence(host, proc, RelType.EXECUTED, ev, "R-PROC-01", Basis.OBSERVED, {**attrs, "command_line": cmd})
            parent = _process(g, host.name, ev.parent_process, ev.parent_process_id, ts, None)
            if parent is not None:
                g.add_occurrence(parent, proc, RelType.SPAWNED, ev, "R-PROC-02", Basis.OBSERVED, attrs)
        elif cat == "network":
            dst, inferred = g.endpoint(ev.dst_ip, ts)
            if dst is None:
                return
            external = dst.type == EntityType.IP and dst.category == "external"
            g.add_occurrence(proc, dst, RelType.COMMUNICATED_WITH if external else RelType.CONNECTED_TO, ev, "R-NET-01",
                             Basis.INFERRED if inferred else Basis.OBSERVED, {**attrs, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port})
        elif cat == "privilege" and ev.target_user:
            tgt = g.entity(EntityType.USER, ev.target_user, ts, "user")
            g.add_occurrence(proc, tgt, RelType.PRIVILEGE_ESCALATED, ev, "R-PRIV-01", Basis.OBSERVED, attrs)
        elif cat == "service" and ev.service:
            svc = g.entity(EntityType.SERVICE, f"{host.name}/{ev.service}", ts, "service")
            svc.attributes.setdefault("host", host.name)
            g.add_occurrence(proc, svc, RelType.MODIFIED, ev, "R-SVC-01", Basis.OBSERVED, attrs)
    elif cat == "network":
        if ev.outcome != "allowed":
            for v in (ev.src_ip or ev.src_host, ev.dst_ip or ev.dst_host):
                ent, _ = g.endpoint(v, ts)
                if ent is not None:
                    g.entity_events[ent.id].add(ev.uid)
                    g.event_elements[ev.uid].add(ent.id)
            return
        src, s_inf = g.endpoint(ev.src_ip or ev.src_host, ts)
        dst, d_inf = g.endpoint(ev.dst_ip or ev.dst_host, ts)
        if src is None or dst is None:
            return
        external = dst.type == EntityType.IP and dst.category == "external"
        g.add_occurrence(src, dst, RelType.COMMUNICATED_WITH if external else RelType.CONNECTED_TO, ev, "R-NET-02",
                         Basis.INFERRED if (s_inf or d_inf) else Basis.OBSERVED,
                         {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port, "via": ev.action})
    elif cat == "dns" and ev.domain:
        client, inferred = g.endpoint(ev.src_ip, ts)
        dom = g.entity(EntityType.DOMAIN, ev.domain, ts, "domain")
        if client is not None:
            g.add_occurrence(client, dom, RelType.QUERIED, ev, "R-DNS-01", Basis.INFERRED if inferred else Basis.OBSERVED,
                             {"client_ip": ev.src_ip, "rcode": ev.outcome})
        if ev.dst_ip:
            ip = g.entity(EntityType.IP, ev.dst_ip, ts, "internal_unmanaged" if is_private_ip(ev.dst_ip) else "external")
            g.add_occurrence(dom, ip, RelType.RESOLVED_TO, ev, "R-DNS-02", Basis.OBSERVED, {})
    elif cat == "db_access" and ev.database:
        client, inferred = g.endpoint(ev.src_host, ts)
        db = g.entity(EntityType.DATABASE, ev.database, ts, "database")
        if not db.in_inventory and db.criticality < 3:
            db.criticality = 3
        if client is not None:
            g.add_occurrence(client, db, RelType.ACCESSED, ev, "R-DB-01", Basis.INFERRED if inferred else Basis.OBSERVED,
                             {"db_user": ev.user, "operation": ev.action, "rows": ev.raw.get("rows_returned"),
                              "object": ev.raw.get("object")})


def _apply_alert(g: TemporalGraph, ev: NormalizedEvent) -> None:
    alert = g.entity(EntityType.ALERT, ev.event_id, ev.timestamp, "alert")
    alert.attributes.update({"rule": ev.alert_name, "technique": ev.technique, "severity": ev.severity,
                             "disposition": ev.disposition, "status": ev.outcome})
    alert.criticality = 1
    for target in ev.alert_entities:
        etype_s, _, name = target.partition(":")
        etype = EntityType(etype_s)
        if etype == EntityType.IP:
            ent, _ = g.endpoint(name, ev.timestamp)
        else:
            ent = g.entity(etype, name, ev.timestamp, "")
            if etype == EntityType.HOST and not ent.category:
                ent.category = "unmanaged"
        if ent is not None:
            g.add_occurrence(alert, ent, RelType.ALERTED_ON, ev, "R-ALERT-01", Basis.OBSERVED, {"rule": ev.alert_name})


def _host_of(g: TemporalGraph, entity_id: str) -> str:
    ent = g.entities[entity_id]
    if ent.type == EntityType.PROCESS:
        return eid(EntityType.HOST, ent.attributes.get("host", ""))
    return entity_id


def _propagate_alert_suspicion(g: TemporalGraph, alerts: list[NormalizedEvent], window: timedelta) -> None:
    by_event_id = g.by_event_id
    for alert in alerts:
        if (alert.disposition or "") in DISMISSED_DISPOSITIONS:
            continue
        sev = alert.severity
        referenced: set[str] = set()
        for ref in alert.related_event_ids:
            referenced.update([ref] if ref in g.events else by_event_id.get(ref, []))
        for uid in referenced:
            for rid in g.event_elements.get(uid, ()):
                rel = g.rels.get(rid)
                if rel is None:
                    continue
                for occ in rel.occurrences:
                    if occ.event_uid == uid and sev > occ.suspicion:
                        occ.suspicion = sev
                        occ.attributes["suspicion_rule"] = "R-SUSP-01"
                        occ.attributes["alert"] = alert.event_id
        named = set(alert.alert_entities)
        if len(named) < 2:
            continue
        lo, hi = alert.timestamp - window, alert.timestamp + window
        for rel in g.rels.values():
            if rel.type not in TRAVERSABLE:
                continue
            if _host_of(g, rel.source) not in named and rel.source not in named:
                continue
            if _host_of(g, rel.target) not in named and rel.target not in named:
                continue
            for occ in rel.occurrences:
                if lo <= occ.timestamp <= hi and 0.8 * sev > occ.suspicion:
                    occ.suspicion = round(0.8 * sev, 3)
                    occ.attributes["suspicion_rule"] = "R-SUSP-02"
                    occ.attributes["alert"] = alert.event_id


def build_graph(events: Iterable[NormalizedEvent], inventory: Iterable[InventoryItem],
                correlation_window: timedelta = timedelta(minutes=90), deviation: bool = True) -> TemporalGraph:
    g = TemporalGraph()
    g.load_inventory(inventory)
    ordered = sorted(events, key=lambda e: (e.timestamp, e.uid))
    alerts: list[NormalizedEvent] = []
    for ev in ordered:
        g.events[ev.uid] = ev
        g.by_event_id[ev.event_id].append(ev.uid)
        if g.min_time is None or ev.timestamp < g.min_time:
            g.min_time = ev.timestamp
        if g.max_time is None or ev.timestamp > g.max_time:
            g.max_time = ev.timestamp
        if ev.category == "alert":
            alerts.append(ev)
        else:
            _apply_event(g, ev)
    for a in alerts:
        _apply_alert(g, a)
    _propagate_alert_suspicion(g, alerts, correlation_window)
    for rel in g.rels.values():
        rel.occurrences.sort(key=lambda o: (o.timestamp, o.event_uid))
        g._times[rel.id] = [o.timestamp for o in rel.occurrences]
    if deviation:
        from ..deviation import score_deviations
        score_deviations(g)
    return g


class GraphView:

    def __init__(self, g: TemporalGraph) -> None:
        self.g = g

    def out_rels(self, node: str, allowed: set[RelType] | None = None) -> list[Relationship]:
        if node not in self.g.g:
            return []
        out = []
        for _, _, data in self.g.g.out_edges(node, data=True):
            rel = self.g.rels[data["rel_id"]]
            if rel.type in TRAVERSABLE and (allowed is None or rel.type in allowed):
                out.append(rel)
        return out

    def in_rels(self, node: str, allowed: set[RelType] | None = None) -> list[Relationship]:
        if node not in self.g.g:
            return []
        out = []
        for _, _, data in self.g.g.in_edges(node, data=True):
            rel = self.g.rels[data["rel_id"]]
            if rel.type in TRAVERSABLE and (allowed is None or rel.type in allowed):
                out.append(rel)
        return out

    def earliest_after(self, rel: Relationship, t: datetime | None, skew: timedelta) -> int | None:
        times = self.g._times.get(rel.id) or [o.timestamp for o in rel.occurrences]
        if t is None:
            return 0 if times else None
        i = bisect.bisect_left(times, t - skew)
        return i if i < len(times) else None

    def latest_before(self, rel: Relationship, t: datetime | None, skew: timedelta) -> int | None:
        times = self.g._times.get(rel.id) or [o.timestamp for o in rel.occurrences]
        if not times:
            return None
        if t is None:
            return len(times) - 1
        i = bisect.bisect_right(times, t + skew) - 1
        return i if i >= 0 else None
