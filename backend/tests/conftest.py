"""Shared fixtures, including the known-answer scenario used by many tests.

Known-answer graph (all times 2026-01-01, UTC):

    E1 10:00  user-01 logs on to WS-01                      -> user:user-01 -AUTHENTICATED_TO-> host:WS-01
    E2 10:05  evil.exe (pid 100) starts on WS-01, sev 0.9   -> host:WS-01 -EXECUTED-> process:WS-01/evil.exe#100
    E3 10:10  flow WS-01 -> 10.0.0.20 (SRV-01 by inventory) -> host:WS-01 -CONNECTED_TO-> host:SRV-01   (inferred)
    E4 10:20  SRV-01 queries DB-01                          -> host:SRV-01 -ACCESSED-> database:DB-01
    E5 09:00  WS-02 queries DB-01 (BEFORE the logon below)  -> host:WS-02 -ACCESSED-> database:DB-01
    E6 09:30  user-01 logs on to WS-02                      -> user:user-01 -AUTHENTICATED_TO-> host:WS-02
    E7 10:30  flow SRV-01 -> WS-01                          -> cycle WS-01 <-> SRV-01
    E8 10:40  user-99 FAILS to log on to WS-99              -> entities, no edge (disconnected)
    E9 11:00  CORP\\USER-01 logs on to WS-01 again          -> same user entity, 2nd occurrence
    E10 10:12 blocked flow WS-01 -> DB-01 port 1433          -> no edge

Expected: USER-01 -> WS-01 -> SRV-01 -> DB-01 is the only temporally valid route to DB-01;
USER-01 -> WS-02 -> DB-01 exists structurally but is temporally impossible.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from attackgraph.config import AnalysisSettings, DeploymentConfig  # noqa: E402
from attackgraph.workspace import Workspace  # noqa: E402

KAT_FIELDS = ["event_id", "timestamp", "source_system", "category", "action", "outcome", "severity", "user",
              "src_host", "dst_host", "src_ip", "dst_ip", "dst_port", "process", "process_id", "database"]

KAT_ROWS = [
    dict(event_id="E1", timestamp="2026-01-01T10:00:00Z", source_system="idp", category="authentication", outcome="success",
         severity="0.8", user="USER-01", src_host="WS-01", dst_host="WS-01"),
    dict(event_id="E2", timestamp="2026-01-01T10:05:00Z", source_system="edr", category="process", outcome="observed",
         severity="0.9", user="USER-01", src_host="WS-01", process="C:\\Temp\\evil.exe", process_id="100"),
    dict(event_id="E3", timestamp="2026-01-01T10:10:00Z", source_system="netflow", category="network", outcome="allowed",
         src_ip="10.0.0.11", dst_ip="10.0.0.20", dst_port="445"),
    dict(event_id="E4", timestamp="2026-01-01T10:20:00Z", source_system="dbaudit", category="db_access", action="SELECT",
         outcome="success", user="svc", src_host="SRV-01", database="DB-01"),
    dict(event_id="E5", timestamp="2026-01-01T09:00:00Z", source_system="dbaudit", category="db_access", action="SELECT",
         outcome="success", user="svc", src_host="WS-02", database="DB-01"),
    dict(event_id="E6", timestamp="2026-01-01T09:30:00Z", source_system="idp", category="authentication", outcome="success",
         user="user-01", src_host="WS-02", dst_host="WS-02"),
    dict(event_id="E7", timestamp="2026-01-01T10:30:00Z", source_system="netflow", category="network", outcome="allowed",
         src_host="SRV-01", dst_host="WS-01"),
    dict(event_id="E8", timestamp="2026-01-01T10:40:00Z", source_system="idp", category="authentication", outcome="failure",
         user="user-99", dst_host="WS-99"),
    dict(event_id="E9", timestamp="2026-01-01T11:00:00Z", source_system="idp", category="authentication", outcome="success",
         user="CORP\\USER-01", src_host="ws-01.corp.local", dst_host="ws-01.corp.local"),
    dict(event_id="E10", timestamp="2026-01-01T10:12:00Z", source_system="netflow", category="network", outcome="blocked",
         src_ip="10.0.0.11", dst_ip="10.0.0.30", dst_port="1433"),
]

KAT_INVENTORY = """asset_id,asset_type,name,ip,criticality,owner,tags
A1,workstation,WS-01,10.0.0.11,2,it,
A2,server,SRV-01,10.0.0.20,4,it,
A3,database,DB-01,10.0.0.30,5,data,crown_jewel
A4,user,user-01,,2,finance,
"""


def to_csv(rows: list[dict], fields: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({f: r.get(f, "") for f in fields})
    return buf.getvalue().encode()


@pytest.fixture
def kat_files() -> list[tuple[str, bytes, None]]:
    return [("kat_events.csv", to_csv(KAT_ROWS, KAT_FIELDS), None), ("kat_inventory.csv", KAT_INVENTORY.encode(), None)]


@pytest.fixture
def deploy(tmp_path: Path) -> DeploymentConfig:
    return DeploymentConfig(sample_dir=ROOT / "data" / "sample", upload_dir=tmp_path / "uploads",
                            export_dir=tmp_path / "exports", frontend_dist=tmp_path / "no-ui",
                            graph_backend="memory", neo4j_uri=None, neo4j_user=None, neo4j_password=None)


@pytest.fixture
def kat_ws(deploy, kat_files) -> Workspace:
    ws = Workspace(deploy, AnalysisSettings())
    res = ws.ingest(kat_files)
    assert all("error" not in r for r in res), res
    return ws


@pytest.fixture(scope="session")
def sample_ws() -> Workspace:
    d = DeploymentConfig(sample_dir=ROOT / "data" / "sample", graph_backend="memory", neo4j_uri=None,
                         neo4j_user=None, neo4j_password=None)
    ws = Workspace(d, AnalysisSettings())
    ws.load_sample()
    return ws


def jdump(obj) -> bytes:
    return json.dumps(obj).encode()
