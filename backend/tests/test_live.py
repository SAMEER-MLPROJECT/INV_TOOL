"""Live mode: push API, micro-batched rebuilds, Server-Sent Events and attack replay."""
import time

import pytest
from fastapi.testclient import TestClient

from attackgraph.api.app import create_app
from attackgraph.config import AnalysisSettings
from attackgraph.ingest.loader import IngestError
from attackgraph.workspace import Workspace

LOGON = {"event_id": "LIVE-1", "time": "2026-01-01T12:00:00Z", "user": "eve", "src_host": "WS-01",
         "dst_host": "SRV-01", "logon_type": "network", "result": "success"}


def test_pushed_records_enter_the_graph_with_stream_provenance(kat_ws):
    v0 = kat_ws.live.version
    res = kat_ws.live.ingest([LOGON, {**LOGON, "event_id": "LIVE-2", "result": "maybe"}], "idp_auth")
    assert res["accepted"] == 1 and res["rejected"] == 1
    kat_ws.live.flush()
    assert kat_ws.live.version > v0
    rel = kat_ws.graph.rels["user:eve|AUTHENTICATED_TO|host:SRV-01"]
    ev = kat_ws.graph.events[rel.occurrences[0].event_uid]
    assert ev.source_file == "live:idp_auth" and ev.source_row == 1
    again = kat_ws.live.ingest([LOGON], "idp_auth")  # same record re-sent: not double counted
    assert again["accepted"] == 0 and again["duplicates"] == 1
    assert any(f.file_name == "live:idp_auth" for f in kat_ws.files)


def test_stream_validation(kat_ws):
    with pytest.raises(IngestError):
        kat_ws.live.ingest([], None)
    with pytest.raises(IngestError):
        kat_ws.live.ingest([{"foo": 1}], None)
    with pytest.raises(IngestError):
        kat_ws.live.ingest([LOGON], "no-such-source")


def test_every_rebuild_publishes_a_version(deploy, kat_files):
    ws = Workspace(deploy, AnalysisSettings())
    v = ws.live.version
    ws.ingest(kat_files)
    assert ws.live.version == v + 1 and ws.live.last_update["events"] == len(ws.graph.events)
    ws.update_settings(AnalysisSettings(correlation_window_minutes=30))
    assert ws.live.version == v + 2 and ws.live.last_update["reason"] == "settings"


def _wait_replay(c, timeout=60):
    t = time.time()
    while time.time() - t < timeout:
        s = c.get("/api/stream/status").json()
        if not s["replay"]["running"] and (s["replay"]["finished"] or s["replay"]["error"] or s["replay"]["stopped"]):
            return s
        time.sleep(0.2)
    raise AssertionError("replay did not finish")


def test_replay_streams_the_attack_and_the_picture_builds_up(deploy):
    c = TestClient(create_app(Workspace(deploy, AnalysisSettings())))
    r = c.post("/api/stream/replay", json={"start": "2026-10-27T20:25:00Z", "end": "2026-10-27T22:15:00Z", "speed": 5000})
    assert r.status_code == 200
    assert c.post("/api/stream/replay", json={"speed": 10}).status_code in (200, 409)
    s = _wait_replay(c)
    rp = s["replay"]
    assert rp["finished"] and rp["sent"] == rp["total"] > 0 and rp["preloaded"] > 0
    assert s["last_update"]["top_incident"]["priority"] == "Critical"
    assert sum(1 for f in s["feed"] if f["kind"] == "alert") >= 8
    blast = c.get("/api/blast-radius/user:sameer?hops=4").json()
    fin = next(n for n in blast["nodes"] if n["id"] == "database:FINANCE-DB")
    assert fin["classification"] == "SUSPECTED_LATERAL_MOVEMENT"
    files = {f["file_name"] for f in c.get("/api/datasets").json()["files"]}
    assert {"live:edr", "live:idp_auth", "live:db_audit", "live:siem_alerts"} <= files


def test_replay_can_be_stopped(deploy):
    c = TestClient(create_app(Workspace(deploy, AnalysisSettings())))
    c.post("/api/stream/replay", json={"start": "2026-10-27T20:25:00Z", "end": "2026-10-27T22:15:00Z", "speed": 1})
    time.sleep(1.0)
    c.post("/api/stream/replay/stop")
    s = _wait_replay(c)
    assert s["replay"]["stopped"] and s["replay"]["sent"] < s["replay"]["total"]


def test_server_sent_events_and_push_endpoint(deploy):
    c = TestClient(create_app(Workspace(deploy, AnalysisSettings())))
    with c.stream("GET", "/api/stream/updates?max_updates=1") as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        lines = [ln for ln in resp.iter_lines() if ln]
    assert lines[0] == "event: update" and lines[1].startswith("data: {")
    r = c.post("/api/stream/events", json={"records": [LOGON]})
    assert r.status_code == 200 and r.json()["source_type"] == "idp_auth"
    assert c.post("/api/stream/events", json={"records": []}).status_code == 422
    assert c.post("/api/stream/events", json={"records": [{"foo": 1}]}).status_code == 422
    assert c.post("/api/stream/replay", json={"speed": 0}).status_code == 422
    c.post("/api/stream/flush")
    assert c.get("/api/entities/user:eve").status_code == 200
