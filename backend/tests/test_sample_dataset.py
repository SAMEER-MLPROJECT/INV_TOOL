"""Known-answer checks on the synthetic enterprise dataset (see data/sample/EXPECTED_OUTCOMES.md)."""
import hashlib
import subprocess
import sys
from pathlib import Path

from attackgraph.graph.paths import PathQuery

ROOT = Path(__file__).resolve().parents[2]


def test_ingestion_flags_planted_bad_records(sample_ws):
    files = {f.file_name: f for f in sample_ws.files}
    auth = files["auth_logs.csv"]
    assert (auth.duplicates, auth.rejected) == (1, 3)
    fw = files["firewall.csv"]
    assert (fw.conflicts, fw.rejected) == (1, 1)
    assert files["edr_events.jsonl"].rejected == 1  # truncated line
    assert files["dns.json"].warnings > 0  # +05:30 timestamps converted to UTC
    assert len(sample_ws.graph.events) == sum(f.accepted for f in sample_ws.files if f.adapter != "asset_inventory")


def test_principal_attack_path(sample_ws):
    res = sample_ws.paths(PathQuery("user:sameer", ["database:FINANCE-DB"], max_hops=5))
    top = res["paths"][0]
    assert top["priority"] == "Critical" and top["suspicious_hops"] == top["hops"]
    principal = ["user:sameer", "host:WS-014", "process:WS-014/powershell.exe#7344", "host:SRV-APP-02", "database:FINANCE-DB"]
    assert principal in [p["nodes"] for p in res["paths"]]
    p = next(p for p in res["paths"] if p["nodes"] == principal)
    assert [s["relationship"] for s in p["steps"]] == ["AUTHENTICATED_TO", "EXECUTED", "CONNECTED_TO", "ACCESSED"]
    assert p["steps"][0]["timestamp"].startswith("2026-10-27T20:40")  # the off-hours logon, not a routine one
    assert p["steps"][-1]["description"].endswith("48211 rows")
    # benign look-alike: the finance web-app route exists but ranks lower
    benign = next(p for p in res["paths"] if "host:APP-01" in p["nodes"])
    assert benign["suspicious_hops"] == 0 and benign["score"] < top["score"] - 20


def test_backup_route_rejected_as_temporally_impossible(sample_ws):
    res = sample_ws.paths(PathQuery("user:sameer", ["database:FINANCE-DB"], max_hops=5))
    assert any("host:BKP-01" in r["nodes"] for r in res["rejected_temporally_impossible"])
    assert all("host:BKP-01" not in p["nodes"] for p in res["paths"])


def test_blast_radius_distinguishes_attack_from_admin(sample_ws):
    attacker = {n["id"]: n for n in sample_ws.blast("user:sameer", 4, True, None, True)["nodes"]}
    admin = {n["id"]: n for n in sample_ws.blast("user:a.verma", 4, True, None, True)["nodes"]}
    assert attacker["database:FINANCE-DB"]["classification"] == "SUSPECTED_LATERAL_MOVEMENT"
    assert admin["database:FINANCE-DB"]["classification"] == "POTENTIAL_EXPOSURE"
    assert not any(n["classification"] == "SUSPECTED_LATERAL_MOVEMENT" for n in admin.values())


def test_unmanaged_ip_kept_as_ip_entity(sample_ws):
    ent = sample_ws.graph.entities["ip:10.10.9.77"]
    assert ent.category == "internal_unmanaged" and not ent.in_inventory


def test_generator_is_deterministic(tmp_path):
    out = tmp_path / "regen"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_sample_data.py"), "--out", str(out)], check=True,
                   capture_output=True)
    for f in (ROOT / "data" / "sample").iterdir():
        if f.suffix in {".csv", ".json", ".jsonl"}:
            assert hashlib.sha256(f.read_bytes()).hexdigest() == hashlib.sha256((out / f.name).read_bytes()).hexdigest(), f.name
