"""Application service: owns the loaded datasets, the graph and analysis settings."""
from __future__ import annotations

import hashlib
import logging
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import AnalysisSettings, DeploymentConfig
from .correlate import correlate
from .evidence import build_manifest
from .graph.blast import compute_blast_radius
from .graph.builder import TemporalGraph, build_graph
from .graph.paths import PathQuery, find_paths
from .ingest.loader import ALLOWED_EXTENSIONS, FileResult, IngestError, InventoryItem, ingest_bytes, sanitize_filename
from .models import NormalizedEvent
from .report import incident_report, to_html, to_json, to_markdown

log = logging.getLogger(__name__)
STATUSES = {"confirmed", "cleared"}


class Workspace:
    def __init__(self, deploy: DeploymentConfig | None = None, settings: AnalysisSettings | None = None) -> None:
        self.deploy = deploy or DeploymentConfig()
        self.settings = settings or AnalysisSettings()
        self._lock = threading.RLock()
        self.files: list[FileResult] = []
        self.events: dict[str, NormalizedEvent] = {}
        self._digests: dict[str, str] = {}
        self.inventory: list[InventoryItem] = []
        self.cross_file: Counter = Counter()
        self.statuses: dict[str, str] = {}
        self.exports: list[dict] = []
        self.graph: TemporalGraph = build_graph([], [])
        self._incidents: list[dict] | None = None
        self.neo4j = None
        self.neo4j_state: dict = {"configured": bool(self.deploy.neo4j_uri), "connected": False, "synced": False,
                                  "message": "not configured" if not self.deploy.neo4j_uri else "not yet connected"}

    # ---------------------------------------------------------------- ingestion
    def reset(self) -> None:
        with self._lock:
            self.files, self.events, self._digests, self.inventory = [], {}, {}, []
            self.cross_file = Counter()
            self.statuses, self._incidents = {}, None
            self.graph = build_graph([], [])

    def _add(self, res: FileResult) -> None:
        for ev in res.events:
            digest = hashlib.sha256(repr(sorted(ev.raw.items())).encode()).hexdigest()
            if ev.uid in self.events:
                key = "duplicate" if self._digests[ev.uid] == digest else "conflict"
                self.cross_file[key] += 1
                res.add_issue(ev.source_row, key, f"event {ev.uid} already loaded from {self.events[ev.uid].source_file}; "
                                                  + ("ignored" if key == "duplicate" else "first copy kept"))
                if key == "duplicate":
                    res.duplicates += 1
                else:
                    res.conflicts += 1
                res.accepted -= 1
                continue
            self.events[ev.uid] = ev
            self._digests[ev.uid] = digest
        self.inventory.extend(res.inventory)
        self.files.append(res)

    def ingest(self, items: list[tuple[str, bytes, str | None]]) -> list[dict]:
        """``items`` = [(file name, content, optional source type)]. Returns per-file summaries or errors."""
        out = []
        with self._lock:
            for name, data, hint in items:
                try:
                    res = ingest_bytes(data, name, max_bytes=self.deploy.max_upload_bytes,
                                       max_records=self.deploy.max_records_per_file, source_hint=hint or None)
                except IngestError as exc:
                    out.append({"file_name": sanitize_filename(name) if name else "?", "error": str(exc)})
                    continue
                self._add(res)
                out.append(res.summary())
            self.rebuild()
        return out

    def load_directory(self, directory: Path) -> list[dict]:
        items = [(p.name, p.read_bytes(), None) for p in sorted(directory.iterdir())
                 if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS]
        return self.ingest(items)

    def load_sample(self) -> list[dict]:
        with self._lock:
            self.reset()
            return self.load_directory(self.deploy.sample_dir)

    def rebuild(self) -> None:
        with self._lock:
            window = timedelta(minutes=self.settings.correlation_window_minutes)
            self.graph = build_graph(self.events.values(), self.inventory, window)
            self._incidents = None
            if self.neo4j_state.get("synced"):
                self.neo4j_state["synced"] = False
                self.neo4j_state["message"] = "graph changed since last sync"

    # ----------------------------------------------------------------- analysis
    @property
    def incidents(self) -> list[dict]:
        with self._lock:
            if self._incidents is None:
                self._incidents = correlate(self.graph, self.settings, self.statuses)
            return self._incidents

    def incident(self, inc_id: str) -> dict | None:
        return next((i for i in self.incidents if i["id"] == inc_id), None)

    def _provider(self):
        if self.deploy.graph_backend == "neo4j" and self.neo4j is not None and self.neo4j_state.get("synced"):
            return lambda s, t, h: self.neo4j.candidate_paths(s, t, h)
        return None

    def paths(self, q: PathQuery) -> dict:
        with self._lock:
            return find_paths(self.graph, q, self.settings, self._provider())

    def blast(self, entity: str, hops: int, temporal: bool, since: datetime | None, include_processes: bool) -> dict:
        with self._lock:
            return compute_blast_radius(self.graph, entity, self.settings, hops, temporal, since,
                                        include_processes=include_processes, statuses=self.statuses)

    def set_status(self, entity: str, status: str | None) -> None:
        if entity not in self.graph.entities:
            raise KeyError(entity)
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {sorted(STATUSES)} or null")
        with self._lock:
            if status is None:
                self.statuses.pop(entity, None)
            else:
                self.statuses[entity] = status
            self._incidents = None

    def update_settings(self, new: AnalysisSettings) -> None:
        with self._lock:
            window_changed = new.correlation_window_minutes != self.settings.correlation_window_minutes
            self.settings = new
            if window_changed:
                self.rebuild()  # R-SUSP-02 depends on the window
            self._incidents = None

    # ----------------------------------------------------------------- summaries
    def file_summaries(self) -> list[dict]:
        return [f.summary() for f in self.files]

    def summary(self) -> dict:
        g = self.graph
        types = Counter(e.type.value for e in g.entities.values())
        rel_types = Counter(r.type.value for r in g.rels.values())
        sources = Counter(e.source_system for e in g.events.values())
        critical = sorted((e for e in g.entities.values() if e.criticality >= 4), key=lambda e: (-e.criticality, e.id))
        incs = self.incidents
        totals = Counter()
        for f in self.files:
            totals.update({"records_read": f.records_read, "accepted": f.accepted, "rejected": f.rejected,
                           "duplicates": f.duplicates, "conflicts": f.conflicts, "warnings": f.warnings})
        # hourly event histogram for the overview timeline
        hist: Counter = Counter()
        sus_hist: Counter = Counter()
        for ev in g.events.values():
            key = ev.timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
            hist[key] += 1
            if ev.category == "alert" or ev.severity >= self.settings.suspicion_threshold:
                sus_hist[key] += 1
        return {
            "events": len(g.events), "entities": len(g.entities), "relationships": len(g.rels),
            "occurrences": sum(len(r.occurrences) for r in g.rels.values()),
            "entity_types": dict(types), "relationship_types": dict(rel_types), "events_by_source": dict(sources),
            "source_systems": len(sources), "files": len(self.files), "ingestion": dict(totals),
            "time_range": {"start": g.min_time.isoformat() if g.min_time else None, "end": g.max_time.isoformat() if g.max_time else None},
            "critical_assets": [{"id": e.id, "name": e.name, "type": e.type.value, "category": e.category, "criticality": e.criticality}
                                for e in critical],
            "incidents": len(incs),
            "incidents_by_priority": dict(Counter(i["priority"] for i in incs)),
            "top_incident": ({k: incs[0][k] for k in ("id", "title", "priority", "score", "start", "end", "identities",
                                                      "affected_assets", "independent_sources")} | {"hypothesis_nodes": (incs[0]["hypothesis"] or {}).get("nodes")})
            if incs else None,
            "histogram": [{"hour": k, "events": hist[k], "suspicious": sus_hist.get(k, 0)} for k in sorted(hist)],
            "backend": self.backend_status(),
        }

    def entity_list(self, etype: str | None = None, q: str | None = None, limit: int = 500) -> list[dict]:
        out = []
        for e in self.graph.entities.values():
            if etype and e.type.value != etype:
                continue
            if q and q.lower() not in e.id.lower():
                continue
            out.append({"id": e.id, "type": e.type.value, "name": e.name, "category": e.category,
                        "criticality": e.criticality, "in_inventory": e.in_inventory,
                        "degree": self.graph.g.degree(e.id), "events": len(self.graph.entity_events.get(e.id, ())),
                        "status": self.statuses.get(e.id)})
        out.sort(key=lambda x: (-x["criticality"], x["id"]))
        return out[:limit]

    # -------------------------------------------------------------------- exports
    def export_incident(self, inc_id: str, fmt: str) -> tuple[str, bytes, str]:
        inc = self.incident(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        rep = incident_report(self.graph, inc, self.file_summaries(), self.settings.model_dump())
        if fmt == "json":
            body, mime = to_json(rep).encode(), "application/json"
        elif fmt == "md":
            body, mime = to_markdown(rep).encode(), "text/markdown; charset=utf-8"
        elif fmt == "html":
            body, mime = to_html(rep).encode(), "text/html; charset=utf-8"
        else:
            raise ValueError("format must be json, md or html")
        name = f"{inc_id}_report.{fmt}"
        digest = hashlib.sha256(body).hexdigest()
        rec = {"file_name": name, "sha256": digest, "size_bytes": len(body), "incident": inc_id,
               "exported_at": datetime.now(timezone.utc).isoformat()}
        with self._lock:
            self.exports.append(rec)
            try:
                self.deploy.export_dir.mkdir(parents=True, exist_ok=True)
                (self.deploy.export_dir / name).write_bytes(body)
            except OSError:  # exports are also returned directly; disk copy is best-effort
                log.warning("could not write export copy to disk")
        return name, body, mime

    def manifest(self) -> dict:
        return build_manifest(self.file_summaries(), self.exports, len(self.graph.events))

    # -------------------------------------------------------------------- backend
    def backend_status(self) -> dict:
        return {"mode": self.deploy.graph_backend, "local_engine": "NetworkX temporal graph (in-memory)",
                "neo4j": {**self.neo4j_state, "uri_host": _host_only(self.deploy.neo4j_uri), "database": self.deploy.neo4j_database}}

    def neo4j_connect_and_sync(self, factory=None) -> dict:
        from .store.neo4j_store import Neo4jGraphStore, Neo4jUnavailable
        d = self.deploy
        try:
            if self.neo4j is None:
                self.neo4j = Neo4jGraphStore(d.neo4j_uri or "", d.neo4j_user or "", d.neo4j_password or "", d.neo4j_database,
                                             driver_factory=factory)
            info = self.neo4j.verify()
            res = self.neo4j.sync(self.graph)
            self.neo4j_state.update({"configured": True, "connected": True, "synced": True, "server": info,
                                     "last_sync": datetime.now(timezone.utc).isoformat(), "synced_counts": res,
                                     "message": f"synced {res['nodes']} nodes and {res['relationships']} relationships"})
        except Neo4jUnavailable as exc:
            self.neo4j_state.update({"connected": False, "synced": False, "message": str(exc)})
        except Exception as exc:  # driver/network errors: report the class only, never credentials
            log.warning("neo4j sync failed: %s", type(exc).__name__)
            self.neo4j = None
            self.neo4j_state.update({"connected": False, "synced": False, "message": f"connection failed ({type(exc).__name__})"})
        return self.backend_status()


def _host_only(uri: str | None) -> str | None:
    if not uri:
        return None
    rest = uri.split("://", 1)[-1]
    return rest.split("@")[-1].split("/")[0]
