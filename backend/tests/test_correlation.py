import json

from attackgraph.config import AnalysisSettings
from attackgraph.workspace import Workspace


def alert(aid, t, rule, sev, users=(), hosts=(), refs=(), disposition="undetermined"):
    return {"alert_id": aid, "created": t, "rule_name": rule, "severity": sev, "disposition": disposition,
            "entities": {"users": list(users), "hosts": list(hosts)}, "evidence_refs": list(refs)}


def build(deploy, kat_files, alerts, **settings):
    ws = Workspace(deploy, AnalysisSettings(**settings))
    ws.ingest(kat_files + [("alerts.json", json.dumps({"alerts": alerts}).encode(), None)])
    return ws


def test_related_alerts_grouped_unrelated_kept_apart(deploy, kat_files):
    ws = build(deploy, kat_files, [
        alert("A1", "2026-01-01T10:01:00Z", "Suspicious logon", "high", users=["user-01"], hosts=["WS-01"], refs=["E1"]),
        alert("A2", "2026-01-01T10:06:00Z", "Malware", "critical", hosts=["WS-01"], refs=["E2"]),
        alert("A3", "2026-01-01T10:21:00Z", "Bulk read", "high", hosts=["SRV-01"], refs=["E4"]),
        alert("B1", "2026-01-01T18:00:00Z", "Unrelated", "medium", hosts=["WS-77"]),
    ])
    incs = ws.incidents
    big = next(i for i in incs if any(a["rule"] == "Malware" for a in i["alerts"]))
    assert {a["rule"] for a in big["alerts"]} == {"Suspicious logon", "Malware", "Bulk read"}
    rules = {l["rule"] for l in big["correlation_links"]}
    assert "R-COR-01" in rules and ("R-COR-02" in rules or "R-COR-03" in rules)
    other = next(i for i in incs if any(a["rule"] == "Unrelated" for a in i["alerts"]))
    assert other["id"] != big["id"] and len(other["alerts"]) == 1
    assert big["score"] > other["score"]
    for i in incs:
        for k in ("id", "start", "end", "affected_assets", "identities", "supporting_events", "evidence_sources",
                  "explanation", "priority", "breakdown"):
            assert k in i
    assert "idp:E1" in big["supporting_events"] and "edr:E2" in big["supporting_events"]


def test_correlation_window_is_configurable(deploy, kat_files):
    alerts = [alert("A1", "2026-01-01T10:00:00Z", "One", "high", hosts=["WS-01"]),
              alert("A2", "2026-01-01T10:50:00Z", "Two", "high", hosts=["WS-01"])]
    wide = build(deploy, kat_files, alerts, correlation_window_minutes=60)
    narrow = build(deploy, kat_files, alerts, correlation_window_minutes=30)
    assert len([i for i in wide.incidents if i["alerts"]]) == 1
    assert len([i for i in narrow.incidents if i["alerts"]]) == 2


def test_benign_disposition_reduces_priority(deploy, kat_files):
    ws = build(deploy, kat_files, [alert("S1", "2026-01-01T18:00:00Z", "Scan", "high", hosts=["SCN"], disposition="benign_true_positive")])
    inc = next(i for i in ws.incidents if i["alerts"])
    assert inc["dismissed_by_source"] and inc["priority"] == "Low"


def test_independent_sources_counted_by_system_not_record(deploy, kat_files):
    alerts = [alert(f"A{i}", f"2026-01-01T10:0{i}:00Z", f"Same source {i}", "high", hosts=["WS-01"]) for i in range(4)]
    ws = build(deploy, kat_files, alerts)
    inc = next(i for i in ws.incidents if len(i["alerts"]) == 4)
    assert inc["evidence_sources"].count("siem_alerts") == 1


def test_sample_incidents(sample_ws):
    incs = sample_ws.incidents
    top = incs[0]
    assert top["priority"] == "Critical"
    assert len(top["alerts"]) == 8
    assert "user:sameer" in top["identities"] and "database:FINANCE-DB" in top["affected_assets"]
    assert top["hypothesis"]["nodes"][0] == "user:sameer" and top["hypothesis"]["target"] == "database:FINANCE-DB"
    scan = next(i for i in incs if i["title"] == "Internal port scan")
    assert scan["dismissed_by_source"] and scan["priority"] == "Low"
    edr_only = next(i for i in incs if not i["alerts"])
    assert edr_only["independent_sources"] == 1
