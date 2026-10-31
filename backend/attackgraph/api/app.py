"""HTTP API (FastAPI) and static hosting of the built web UI."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..config import AnalysisSettings
from ..containment import WhatIfError
from ..evidence import explain_entity, explain_event, explain_relationship
from ..graph.blast import BlastError
from ..graph.paths import PathError, PathQuery
from ..ingest.loader import IngestError
from ..ingest.normalize import NormalizationError, parse_timestamp
from ..ingest.sources import ADAPTERS
from ..models import TRAVERSABLE, RelType
from ..rules import RULES
from ..workspace import Workspace

log = logging.getLogger("attackgraph.api")
MAX_FILES_PER_UPLOAD = 12
MAX_GRAPH_NODES = 600


class PathRequest(BaseModel):
    source: str
    targets: list[str] | None = None
    max_hops: int = Field(default=5, ge=1, le=8)
    max_paths: int = Field(default=12, ge=1, le=100)
    rel_types: list[RelType] | None = None
    since: str | None = None


class WhatIfRequest(BaseModel):
    source: str
    actions: list[str] = Field(min_length=1, max_length=8)
    at: str | None = None
    hops: int = Field(default=5, ge=1, le=8)


class StreamBatch(BaseModel):
    source_type: str | None = None
    records: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class ReplayRequest(BaseModel):
    start: str | None = None
    end: str | None = None
    speed: float = Field(default=120.0, ge=1, le=100_000)


class StatusRequest(BaseModel):
    status: str | None = None


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value)[0]
    except NormalizationError as exc:
        raise HTTPException(422, f"invalid time: {exc}") from exc


def create_app(ws: Workspace | None = None, load_sample: bool = True) -> FastAPI:
    ws = ws or Workspace()
    if load_sample and not ws.files and ws.deploy.sample_dir.is_dir():
        ws.load_sample()

    app = FastAPI(title="AttackGraph Lens API", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.ws = ws
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # never leak stack traces to users
        ref = uuid.uuid4().hex[:8]
        log.error("unhandled error ref=%s path=%s type=%s", ref, request.url.path, type(exc).__name__)
        return JSONResponse({"detail": f"Internal error (reference {ref}). See server log."}, status_code=500)

    # ------------------------------------------------------------------ meta
    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "events": len(ws.graph.events), "entities": len(ws.graph.entities),
                "backend": ws.backend_status()}

    @app.get("/api/summary")
    def summary() -> dict:
        return ws.summary()

    @app.get("/api/rules")
    def rules() -> dict:
        return RULES

    @app.get("/api/sources")
    def sources() -> list[dict]:
        return [{"name": a.name, "label": a.label, "required_fields": sorted(a.signature), "id_field": a.id_field,
                 "time_field": a.time_field, "context": a.is_context} for a in ADAPTERS]

    # -------------------------------------------------------------- datasets
    @app.get("/api/datasets")
    def datasets() -> dict:
        return {"files": ws.file_summaries(), "cross_file": dict(ws.cross_file)}

    @app.post("/api/datasets/sample")
    def reset_sample() -> dict:
        return {"files": ws.load_sample()}

    @app.post("/api/datasets/clear")
    def clear() -> dict:
        ws.reset()
        return {"status": "cleared"}

    @app.post("/api/datasets/upload")
    async def upload(files: list[UploadFile] = File(...), source_type: str = Form(""), mode: str = Form("append")) -> dict:
        if mode not in {"append", "replace"}:
            raise HTTPException(422, "mode must be append or replace")
        if len(files) > MAX_FILES_PER_UPLOAD:
            raise HTTPException(413, f"at most {MAX_FILES_PER_UPLOAD} files per upload")
        items = []
        for f in files:
            data = await f.read(ws.deploy.max_upload_bytes + 1)  # bounded read
            if len(data) > ws.deploy.max_upload_bytes:
                raise HTTPException(413, f"{f.filename}: larger than {ws.deploy.max_upload_bytes // (1024 * 1024)} MB")
            items.append((f.filename or "upload", data, source_type or None))
        if mode == "replace":
            ws.reset()
        return {"files": ws.ingest(items)}

    # ---------------------------------------------------------------- graph
    @app.get("/api/entities")
    def entities(type: str | None = None, q: str | None = None, limit: int = Query(500, ge=1, le=5000)) -> list[dict]:
        return ws.entity_list(type, q, limit)

    @app.get("/api/entities/{entity_id:path}")
    def entity(entity_id: str) -> dict:
        res = explain_entity(ws.graph, entity_id, ws.statuses)
        if res is None:
            raise HTTPException(404, "entity not found")
        res["incidents"] = [i["id"] for i in ws.incidents if any(entity_id in v for v in i["entities"].values())]
        return res

    @app.post("/api/entities/{entity_id:path}/status")
    def set_status(entity_id: str, body: StatusRequest) -> dict:
        try:
            ws.set_status(entity_id, body.status)
        except KeyError:
            raise HTTPException(404, "entity not found") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"entity": entity_id, "status": body.status}

    @app.get("/api/relationships/{rel_id:path}")
    def relationship(rel_id: str) -> dict:
        res = explain_relationship(ws.graph, rel_id)
        if res is None:
            raise HTTPException(404, "relationship not found")
        uids = {o["event_uid"] for o in res["occurrences"]}
        res["incidents"] = [i["id"] for i in ws.incidents if uids & set(i["supporting_events"])]
        return res

    @app.get("/api/graph")
    def graph(
        types: str | None = None, rels: str | None = None, since: str | None = None, until: str | None = None,
        focus: str | None = None, depth: int = Query(1, ge=0, le=4), min_suspicion: float = Query(0.0, ge=0, le=1),
        include_context: bool = False, limit: int = Query(300, ge=1, le=MAX_GRAPH_NODES),
    ) -> dict:
        g = ws.graph
        t0, t1 = _ts(since), _ts(until)
        type_set = set(types.split(",")) if types else None
        try:
            rel_set = {RelType(r) for r in rels.split(",")} if rels else None
        except ValueError as exc:
            raise HTTPException(422, "unknown relationship type") from exc
        allowed_rels = rel_set or (set(RelType) if include_context else set(TRAVERSABLE))

        def rel_ok(r) -> bool:
            if r.type not in allowed_rels:
                return False
            occ = [o for o in r.occurrences if (t0 is None or o.timestamp >= t0) and (t1 is None or o.timestamp <= t1)]
            return bool(occ) and max(o.suspicion for o in occ) >= min_suspicion

        node_ok = lambda n: type_set is None or g.entities[n].type.value in type_set  # noqa: E731
        if focus:
            if focus not in g.entities:
                raise HTTPException(404, "focus entity not found")
            keep = {focus}
            frontier = {focus}
            for _ in range(depth):
                nxt = set()
                for n in frontier:
                    for u, v, d in list(g.g.out_edges(n, data=True)) + list(g.g.in_edges(n, data=True)):
                        if rel_ok(g.rels[d["rel_id"]]):
                            other = v if u == n else u
                            if node_ok(other) and other not in keep:
                                nxt.add(other)
                keep |= nxt
                frontier = nxt
                if len(keep) > limit:
                    break
        else:
            keep = {r.source for r in g.rels.values() if rel_ok(r)} | {r.target for r in g.rels.values() if rel_ok(r)}
            keep = {n for n in keep if node_ok(n)}
        truncated = len(keep) > limit
        if truncated:  # keep the most critical / most connected nodes
            keep = set(sorted(keep, key=lambda n: (n != focus, -g.entities[n].criticality, -g.g.degree(n), n))[:limit])
        nodes = [{"id": n, "type": g.entities[n].type.value, "name": g.entities[n].name, "category": g.entities[n].category,
                  "criticality": g.entities[n].criticality, "in_inventory": g.entities[n].in_inventory,
                  "status": ws.statuses.get(n)} for n in sorted(keep)]
        edges = []
        for r in g.rels.values():
            if r.source in keep and r.target in keep and rel_ok(r):
                edges.append({"id": r.id, "source": r.source, "target": r.target, "type": r.type.value,
                              "count": len(r.occurrences), "basis": r.basis.value, "max_suspicion": round(r.max_suspicion, 3),
                              "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat()})
        return {"nodes": nodes, "edges": edges, "truncated": truncated, "limit": limit}

    # ------------------------------------------------------------- analytics
    @app.post("/api/paths")
    def paths(req: PathRequest) -> dict:
        q = PathQuery(source=req.source, targets=req.targets or None, max_hops=req.max_hops, max_paths=req.max_paths,
                      rel_types=set(req.rel_types) if req.rel_types else None, since=_ts(req.since))
        try:
            return ws.paths(q)
        except PathError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/blast-radius/{entity_id:path}")
    def blast(entity_id: str, hops: int = Query(3, ge=1, le=8), temporal: bool = True, since: str | None = None,
              include_processes: bool = True) -> dict:
        try:
            return ws.blast(entity_id, hops, temporal, _ts(since), include_processes)
        except BlastError as exc:
            raise HTTPException(404 if "unknown" in str(exc) else 422, str(exc)) from exc

    @app.get("/api/incidents")
    def incidents() -> list[dict]:
        keys = ("id", "title", "priority", "score", "start", "end", "identities", "affected_assets", "independent_sources",
                "evidence_sources", "dismissed_by_source")
        return [{k: i[k] for k in keys} | {"alerts": len(i["alerts"]), "seeds": len(i["seed_events"]),
                                           "supporting_events": len(i["supporting_events"])} for i in ws.incidents]

    @app.get("/api/incidents/{inc_id}")
    def incident(inc_id: str) -> dict:
        inc = ws.incident_detail(inc_id)
        if inc is None:
            raise HTTPException(404, "incident not found")
        return inc

    @app.get("/api/incidents/{inc_id}/containment")
    def containment(inc_id: str, at: str | None = None, hops: int = Query(5, ge=1, le=8)) -> dict:
        try:
            return ws.containment(inc_id, _ts(at), hops)
        except KeyError:
            raise HTTPException(404, "incident not found") from None
        except (ValueError, WhatIfError) as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/whatif")
    def whatif(req: WhatIfRequest) -> dict:
        try:
            return ws.what_if(req.source, req.actions, _ts(req.at), req.hops)
        except (WhatIfError, PathError, BlastError) as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/deviations")
    def deviations(limit: int = Query(50, ge=1, le=500)) -> dict:
        return ws.deviations(limit)

    @app.get("/api/incidents/{inc_id}/report")
    def report(inc_id: str, format: str = Query("html", pattern="^(json|md|html)$")) -> Response:
        try:
            name, body, mime = ws.export_incident(inc_id, format)
        except KeyError:
            raise HTTPException(404, "incident not found") from None
        return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # ------------------------------------------------------------------- live
    @app.post("/api/stream/events")
    def stream_events(batch: StreamBatch, request: Request) -> dict:
        if int(request.headers.get("content-length") or 0) > ws.deploy.max_upload_bytes:
            raise HTTPException(413, "batch too large")
        try:
            return ws.live.ingest(batch.records, batch.source_type)
        except IngestError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/stream/flush")
    def stream_flush() -> dict:
        ws.live.flush()
        return ws.live.status()

    @app.get("/api/stream/status")
    def stream_status() -> dict:
        return ws.live.status()

    @app.post("/api/stream/replay")
    def stream_replay(req: ReplayRequest) -> dict:
        try:
            return ws.live.start_replay(_ts(req.start), _ts(req.end), req.speed)
        except IngestError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/stream/replay/stop")
    def stream_replay_stop() -> dict:
        return ws.live.stop_replay()

    @app.get("/api/stream/updates")
    async def stream_updates(request: Request, max_updates: int = Query(0, ge=0, le=10_000)):
        """Server-Sent Events: one message per graph version (uploads, stream batches, settings, analyst marks)."""
        async def gen():
            last, sent, idle = -1, 0, 0.0
            while True:
                if await request.is_disconnected():
                    break
                if ws.live.version != last:
                    last = ws.live.version
                    payload = json.dumps(ws.live.last_update or {"version": last})
                    yield f"event: update\ndata: {payload}\n\n"
                    sent += 1
                    idle = 0.0
                    if max_updates and sent >= max_updates:
                        break
                elif idle >= 15:
                    yield ": keep-alive\n\n"
                    idle = 0.0
                await asyncio.sleep(0.25)
                idle += 0.25
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # --------------------------------------------------------------- evidence
    @app.get("/api/events")
    def events(q: str | None = None, source: str | None = None, category: str | None = None, entity: str | None = None,
               min_severity: float = Query(0.0, ge=0, le=1), offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)) -> dict:
        g = ws.graph
        pool = (g.events[u] for u in g.entity_events.get(entity, ())) if entity else g.events.values()
        from ..evidence import event_dict
        rows = []
        for ev in pool:
            if source and ev.source_system != source:
                continue
            if category and ev.category != category:
                continue
            if ev.severity < min_severity:
                continue
            d = event_dict(ev)
            if q and q.lower() not in (d["description"] + " " + ev.uid + " " + ev.source_file).lower():
                continue
            rows.append(d)
        rows.sort(key=lambda d: (d["timestamp"], d["uid"]))
        return {"total": len(rows), "offset": offset, "limit": limit, "events": rows[offset:offset + limit]}

    @app.get("/api/events/{uid:path}")
    def event(uid: str) -> dict:
        res = explain_event(ws.graph, uid)
        if res is None:
            raise HTTPException(404, "event not found")
        res["incidents"] = [i["id"] for i in ws.incidents if uid in i["supporting_events"]]
        return res

    @app.get("/api/evidence/manifest")
    def manifest(download: bool = False) -> Any:
        m = ws.manifest()
        if download:
            return Response(json.dumps(m, indent=2), media_type="application/json",
                            headers={"Content-Disposition": 'attachment; filename="evidence_manifest.json"'})
        return m

    # --------------------------------------------------------------- settings
    @app.get("/api/settings")
    def get_settings() -> dict:
        return ws.settings.model_dump()

    @app.put("/api/settings")
    def put_settings(body: AnalysisSettings) -> dict:
        ws.update_settings(body)
        return ws.settings.model_dump()

    @app.post("/api/settings/reset")
    def reset_settings() -> dict:
        ws.update_settings(AnalysisSettings())
        return ws.settings.model_dump()

    @app.get("/api/backend")
    def backend() -> dict:
        return ws.backend_status()

    @app.post("/api/backend/neo4j/sync")
    def neo4j_sync() -> dict:
        if not ws.deploy.neo4j_uri:
            raise HTTPException(409, "Neo4j is not configured. Set NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD and restart.")
        return ws.neo4j_connect_and_sync()

    # ------------------------------------------------------------ static UI
    dist: Path = ws.deploy.frontend_dist
    if (dist / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                raise HTTPException(404, "not found")
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        def no_ui() -> dict:
            return {"message": "AttackGraph Lens API is running. Build the UI with `npm run build` in frontend/, "
                               "or open /api/docs for the API."}

    return app
