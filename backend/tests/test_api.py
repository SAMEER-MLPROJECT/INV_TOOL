import hashlib
import json
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from attackgraph.api.app import create_app
from attackgraph.config import AnalysisSettings
from attackgraph.workspace import Workspace

from .conftest import ROOT


@pytest.fixture
def client(deploy):
    ws = Workspace(deploy, AnalysisSettings())
    return TestClient(create_app(ws, load_sample=True), raise_server_exceptions=False)


def test_health_summary_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    s = client.get("/api/summary").json()
    assert s["events"] > 1000 and s["incidents"] == 4 and s["top_incident"]["priority"] == "Critical"


def test_paths_blast_incident_endpoints(client):
    r = client.post("/api/paths", json={"source": "user:sameer", "targets": ["database:FINANCE-DB"], "max_hops": 5})
    assert r.status_code == 200 and r.json()["paths"]
    assert client.post("/api/paths", json={"source": "user:sameer", "max_hops": 99}).status_code == 422
    assert client.post("/api/paths", json={"source": "user:ghost", "max_hops": 3}).status_code == 422
    b = client.get("/api/blast-radius/user:sameer?hops=4")
    assert b.status_code == 200 and b.json()["summary"]["reachable"] > 0
    assert client.get("/api/blast-radius/user:sameer?hops=12").status_code == 422
    assert client.get("/api/blast-radius/user:ghost").status_code == 404
    incs = client.get("/api/incidents").json()
    assert client.get(f"/api/incidents/{incs[0]['id']}").json()["hypothesis"]
    assert client.get("/api/incidents/INC-9999").status_code == 404


def test_evidence_endpoints(client):
    rel = "host:SRV-APP-02|ACCESSED|database:FINANCE-DB"
    r = client.get("/api/relationships/" + quote(rel, safe="")).json()
    assert r["occurrence_count"] > 1 and r["rules"][0]["id"] == "R-DB-01"
    occ = max(r["occurrences"], key=lambda o: o["suspicion"])
    ev = client.get("/api/events/" + quote(occ["event_uid"], safe="")).json()
    assert ev["source_file"] == "db_audit.csv" and ev["raw"]["rows_returned"] and rel in ev["graph_relationships"]
    ent = client.get("/api/entities/user:sameer").json()
    assert ent["outbound"] and ent["incidents"]
    page = client.get("/api/events?source=edr&limit=10&offset=5").json()
    assert page["total"] > 10 and len(page["events"]) == 10
    unresolved = [e for e in client.get("/api/events?category=alert&limit=50").json()["events"]
                  if client.get("/api/events/" + quote(e["uid"], safe="")).json()["unresolved_evidence_refs"]]
    assert len(unresolved) == 1


def test_graph_endpoint_filters(client):
    full = client.get("/api/graph?limit=600").json()
    sus = client.get("/api/graph?min_suspicion=0.5").json()
    assert 0 < len(sus["nodes"]) < len(full["nodes"])
    assert all(e["max_suspicion"] >= 0.5 for e in sus["edges"])
    foc = client.get("/api/graph?focus=user:sameer&depth=1").json()
    assert "user:sameer" in {n["id"] for n in foc["nodes"]}
    only = client.get("/api/graph?rels=ACCESSED&limit=600").json()
    assert {e["type"] for e in only["edges"]} == {"ACCESSED"}
    timed = client.get("/api/graph?since=2026-10-27T20:00:00Z&until=2026-10-27T23:00:00Z&limit=600").json()
    assert all(e["last_seen"] >= "2026-10-27T20:00" for e in timed["edges"])
    assert client.get("/api/graph?rels=NOPE").status_code == 422
    assert client.get("/api/graph?since=garbage").status_code == 422


def test_upload_valid_invalid_and_traversal(client):
    data = (ROOT / "data" / "sample" / "auth_logs.csv").read_bytes()
    r = client.post("/api/datasets/upload", files=[("files", ("../../etc/auth.csv", data, "text/csv"))],
                    data={"mode": "replace", "source_type": ""})
    assert r.status_code == 200
    res = r.json()["files"][0]
    assert res["file_name"] == "auth.csv" and res["source_system"] == "idp_auth"
    bad = client.post("/api/datasets/upload", files=[("files", ("x.exe", b"MZ", "application/octet-stream"))], data={"mode": "append"})
    assert "unsupported file type" in bad.json()["files"][0]["error"]
    assert client.post("/api/datasets/upload", files=[("files", ("x.csv", b"a", "text/csv"))], data={"mode": "nuke"}).status_code == 422
    big = b"a" * (21 * 1024 * 1024)
    assert client.post("/api/datasets/upload", files=[("files", ("big.csv", big, "text/csv"))], data={"mode": "append"}).status_code == 413
    assert client.post("/api/datasets/sample").status_code == 200


def test_settings_validation_and_recompute(client):
    s = client.get("/api/settings").json()
    s["correlation_window_minutes"] = 0
    assert client.put("/api/settings", json=s).status_code == 422
    s["correlation_window_minutes"] = 15
    assert client.put("/api/settings", json=s).json()["correlation_window_minutes"] == 15
    assert client.post("/api/settings/reset").json()["correlation_window_minutes"] == 90


def test_analyst_status(client):
    assert client.post("/api/entities/host:WS-014/status", json={"status": "confirmed"}).status_code == 200
    b = client.get("/api/blast-radius/user:sameer?hops=2").json()
    assert next(n for n in b["nodes"] if n["id"] == "host:WS-014")["classification"] == "CONFIRMED_COMPROMISE"
    assert client.post("/api/entities/host:WS-014/status", json={"status": "pwned"}).status_code == 422
    assert client.post("/api/entities/host:NOPE/status", json={"status": "confirmed"}).status_code == 404


def test_report_export_consistency_and_manifest(client):
    inc = client.get("/api/incidents").json()[0]
    full = client.get(f"/api/incidents/{inc['id']}").json()
    r = client.get(f"/api/incidents/{inc['id']}/report?format=json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rep = json.loads(r.content)
    assert rep["incident"]["supporting_events"] == full["supporting_events"]
    assert len(rep["evidence_records"]) == len(full["supporting_events"])
    md = client.get(f"/api/incidents/{inc['id']}/report?format=md").text
    assert all(f["sha256"] in md for f in rep["source_files"])
    html = client.get(f"/api/incidents/{inc['id']}/report?format=html").text
    assert html.startswith("<!doctype html>") and "<script" not in html
    assert client.get(f"/api/incidents/{inc['id']}/report?format=exe").status_code == 422
    man = client.get("/api/evidence/manifest").json()
    sha = hashlib.sha256(r.content).hexdigest()
    assert any(x["sha256"] == sha for x in man["exports"])
    for f in man["source_files"]:
        assert hashlib.sha256((ROOT / "data" / "sample" / f["file_name"]).read_bytes()).hexdigest() == f["sha256"]
    assert "do not independently prove" in man["limitation"]


def test_internal_errors_hide_stack_traces(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(client.app.state.ws, "summary", boom)
    r = client.get("/api/summary")
    assert r.status_code == 500 and "secret" not in r.text and "Traceback" not in r.text and "reference" in r.json()["detail"]


def test_neo4j_sync_requires_configuration(client):
    assert client.post("/api/backend/neo4j/sync").status_code == 409
