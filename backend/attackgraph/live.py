"""Live mode: streaming ingestion, micro-batched graph updates, change notifications and attack replay.

Events can arrive continuously (``POST /api/stream/events``) from a SIEM forwarder, a log
shipper or the built-in replay. Each batch is normalised by the same adapters as file uploads;
the graph, suspicion, MD deviation and incidents are then recomputed in **micro-batches** (at
most one rebuild per ``REBUILD_INTERVAL``), and every rebuild increments a version that is
pushed to browsers over Server-Sent Events so all open views refresh themselves.

Full recomputation per micro-batch (rather than incremental graph patching) keeps a single,
tested code path: on the sample scale a rebuild takes ≈ 0.1 s. Very large streams would need
incremental updates — documented in LIMITATIONS.md.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from .ingest.loader import ALLOWED_EXTENSIONS, FileResult, IngestError, ingest_path, ingest_records

log = logging.getLogger(__name__)

REBUILD_INTERVAL = 0.4  # seconds between micro-batch rebuilds
MAX_BATCH = 5000
FEED_SIZE = 300


class LiveHub:
    def __init__(self, ws) -> None:
        self.ws = ws
        self.cond = threading.Condition()
        self.version = 0
        self.dirty = False
        self.results: dict[str, FileResult] = {}
        self.rows: dict[str, int] = defaultdict(int)
        self.feed: deque = deque(maxlen=FEED_SIZE)
        self.streamed = 0
        self.last_rebuild_ms = 0.0
        self.last_update: dict = {}
        self._applier: threading.Thread | None = None
        self._stop = threading.Event()
        self.replay = ReplayState()

    # ---------------------------------------------------------------- changes
    def publish(self, reason: str) -> None:
        """Called after every graph rebuild (uploads, settings, stream batches)."""
        s = self.ws.graph
        incs = self.ws.incidents
        top = incs[0] if incs else None
        update = {
            "version": self.version + 1, "reason": reason, "at": datetime.now(timezone.utc).isoformat(),
            "events": len(s.events), "entities": len(s.entities), "relationships": len(s.rels), "incidents": len(incs),
            "top_incident": {k: top[k] for k in ("id", "title", "priority", "score")} if top else None,
            "data_time": s.max_time.isoformat() if s.max_time else None,
            "rebuild_ms": round(self.last_rebuild_ms, 1), "streamed": self.streamed,
        }
        with self.cond:
            self.version += 1
            self.last_update = update
            self.cond.notify_all()

    def reset(self) -> None:
        self.results.clear()
        self.rows.clear()
        self.feed.clear()
        self.streamed = 0
        self.dirty = False

    # -------------------------------------------------------------- ingestion
    def ingest(self, records: list, source_type: str | None) -> dict:
        if not isinstance(records, list) or not records:
            raise IngestError("records must be a non-empty list")
        if len(records) > MAX_BATCH:
            raise IngestError(f"at most {MAX_BATCH} records per batch")
        ws = self.ws
        with ws._lock:
            hint = source_type or None
            res = ingest_records(records, source_hint=hint, max_records=MAX_BATCH,
                                 row_offset=self.rows[hint or "auto"])
            key = res.adapter or "auto"
            self.rows[hint or "auto"] += len(records)
            agg = self.results.get(key)
            if agg is None:
                agg = FileResult(file_name=f"live:{key}", sha256="(stream)", size_bytes=0, adapter=res.adapter,
                                 adapter_label=res.adapter_label)
                self.results[key] = agg
                ws.files.append(agg)
            accepted = 0
            for ev in res.events:
                if ev.uid in ws.events:
                    agg.duplicates += 1
                    continue
                ws.events[ev.uid] = ev
                accepted += 1
                if ev.category == "alert":
                    self.feed.appendleft({"kind": "alert", "at": ev.timestamp.isoformat(), "uid": ev.uid,
                                          "text": f"{ev.alert_name} (severity {ev.severity:.2f})"})
            ws.inventory.extend(res.inventory)
            for attr in ("records_read", "rejected", "duplicates", "conflicts", "warnings"):
                setattr(agg, attr, getattr(agg, attr) + getattr(res, attr))
            agg.accepted += accepted + len(res.inventory)
            agg.issues.extend(res.issues[: max(0, 500 - len(agg.issues))])
            for t in (res.first_event, res.last_event):
                if t and (agg.first_event is None or t < agg.first_event):
                    agg.first_event = t
                if t and (agg.last_event is None or t > agg.last_event):
                    agg.last_event = t
            self.streamed += accepted
            self.dirty = True
        self._ensure_applier()
        return {"source_type": res.adapter, "received": len(records), "accepted": accepted,
                "rejected": res.rejected, "duplicates": res.duplicates + (len(res.events) - accepted),
                "issues": [i.model_dump() for i in res.issues[:20]]}

    def flush(self) -> None:
        """Apply pending events now (used by tests and at the end of a replay)."""
        if self.dirty:
            self._apply()

    def _apply(self) -> None:
        t = time.perf_counter()
        with self.ws._lock:
            self.dirty = False
            self.ws.rebuild(publish=False)
            self.last_rebuild_ms = (time.perf_counter() - t) * 1000
        self.publish("stream")

    def _ensure_applier(self) -> None:
        if self._applier is None or not self._applier.is_alive():
            self._applier = threading.Thread(target=self._loop, name="agl-live-applier", daemon=True)
            self._applier.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(REBUILD_INTERVAL)
            if self.dirty:
                try:
                    self._apply()
                except Exception:  # keep the applier alive; details go to the server log only
                    log.exception("live rebuild failed")

    def status(self) -> dict:
        return {"version": self.version, "streamed_events": self.streamed, "pending": self.dirty,
                "last_rebuild_ms": round(self.last_rebuild_ms, 1), "last_update": self.last_update,
                "feed": list(self.feed)[:60], "replay": self.replay.as_dict()}

    # ----------------------------------------------------------------- replay
    def start_replay(self, start: datetime | None, end: datetime | None, speed: float, directory: Path | None = None) -> dict:
        if self.replay.running:
            raise IngestError("a replay is already running")
        if not 1 <= speed <= 100_000:
            raise IngestError("speed must be between 1 and 100000 (data seconds per wall-clock second)")
        directory = directory or self.ws.deploy.sample_dir
        self.replay = ReplayState(running=True, speed=speed)
        t = threading.Thread(target=self._run_replay, args=(directory, start, end, speed), name="agl-replay", daemon=True)
        t.start()
        return self.replay.as_dict()

    def stop_replay(self) -> dict:
        self.replay.stop = True
        return self.replay.as_dict()

    def _run_replay(self, directory: Path, start: datetime | None, end: datetime | None, speed: float) -> None:
        st = self.replay
        try:
            ws = self.ws
            d = ws.deploy
            results = [ingest_path(p, max_bytes=d.max_upload_bytes, max_records=d.max_records_per_file)
                       for p in sorted(directory.iterdir()) if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS]
            with ws._lock:
                ws.reset()
            inventory = [r for r in results if r.adapter == "asset_inventory"]
            for r in inventory:  # context first: the asset inventory is not time-based
                rows = [{"asset_id": i.asset_id, "asset_type": i.asset_type, "name": i.name, "ip": i.ip or "",
                         "criticality": i.criticality, "owner": i.owner or "", "tags": ";".join(i.tags)} for i in r.inventory]
                self.ingest(rows, "asset_inventory")
            events = sorted((ev for r in results for ev in r.events), key=lambda e: (e.timestamp, e.uid))
            if not events:
                raise IngestError("no events to replay")
            start = start or events[0].timestamp
            end = end or events[-1].timestamp
            before = [e for e in events if e.timestamp < start]
            window = [e for e in events if start <= e.timestamp <= end]
            st.total = len(window)
            st.preloaded = len(before)
            st.start, st.end = start.isoformat(), end.isoformat()
            self._push(before)
            self.flush()
            wall0 = time.monotonic()
            i = 0
            while i < len(window) and not st.stop:
                now_data = start.timestamp() + (time.monotonic() - wall0) * speed
                batch = []
                while i < len(window) and window[i].timestamp.timestamp() <= now_data:
                    batch.append(window[i])
                    i += 1
                if batch:
                    self._push(batch)
                    st.sent = i
                st.data_time = datetime.fromtimestamp(min(now_data, end.timestamp()), tz=timezone.utc).isoformat()
                time.sleep(0.1)
            self.flush()
            st.finished = not st.stop
        except Exception as exc:  # report class only
            log.warning("replay failed: %s", type(exc).__name__)
            st.error = str(exc) if isinstance(exc, IngestError) else type(exc).__name__
        finally:
            st.running = False
            self.publish("replay-end")

    def _push(self, events) -> None:
        by_src: dict[str, list] = defaultdict(list)
        for e in events:
            by_src[e.source_system].append(e.raw)
        for src, recs in by_src.items():
            for k in range(0, len(recs), MAX_BATCH):
                self.ingest(recs[k:k + MAX_BATCH], src)


class ReplayState:
    def __init__(self, running: bool = False, speed: float = 0.0) -> None:
        self.running = running
        self.speed = speed
        self.stop = False
        self.finished = False
        self.error: str | None = None
        self.total = 0
        self.sent = 0
        self.preloaded = 0
        self.start: str | None = None
        self.end: str | None = None
        self.data_time: str | None = None

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("running", "speed", "finished", "error", "total", "sent", "preloaded",
                                              "start", "end", "data_time")} | {"stopped": self.stop}
