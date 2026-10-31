from datetime import datetime, timedelta
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from attackgraph.api.app import create_app
from attackgraph.channels import analyse_incident
from attackgraph.config import AnalysisSettings
from attackgraph.containment import WhatIfError, action_for, counterfactual, plan_containment, what_if
from attackgraph.deviation import D2_REFERENCE, SUSPICION_CAP, chi2_4_sf, top_deviations
from attackgraph.graph.paths import PathQuery
from attackgraph.workspace import Workspace

S = AnalysisSettings()
T_ATTACK = datetime.fromisoformat("2026-10-27T20:41:00+00:00")


def test_principal_path_is_corroborated_across_channels(sample_ws):
    res = sample_ws.paths(PathQuery("user:sameer", ["database:FINANCE-DB"], max_hops=5))
    principal = next(p for p in res["paths"] if "process:WS-014/powershell.exe#7344" in p["nodes"] and len(p["nodes"]) == 5)
    ch = principal["channels"]
    assert {"identity", "endpoint", "network", "data", "detection"} <= set(ch["independent_channels"])
    assert ch["multichannel_steps"] == len(principal["steps"])
    assert 0 <= ch["agreement"] <= 1 and ch["agreement"] >= 0.9
    states = [s["cells"][c]["state"] for s in ch["steps"] for c in ch["channels"]]
    assert states.count("primary") == len(principal["steps"])


def test_silent_channel_detected_on_credential_theft_step(sample_ws):
    res = sample_ws.paths(PathQuery("user:sameer", ["database:FINANCE-DB"], max_hops=5))
    cred = next(p for p in res["paths"] if "user:svc_backup" in p["nodes"])
    step = next(s for s in cred["channels"]["steps"] if s["relationship"] == "PRIVILEGE_ESCALATED")
    assert step["cells"]["identity"]["state"] == "silent"
    assert any("PRIVILEGE_ESCALATED" in g for g in cred["channels"]["silent_gaps"])


def test_incident_channel_matrix_flags_single_channel_evidence(sample_ws):
    edr_only = next(i for i in sample_ws.incidents if not i["alerts"])
    ch = analyse_incident(sample_ws.graph, edr_only, timedelta(minutes=90))
    assert ch["channels_with_evidence"] == ["endpoint"]
    assert any("WS-022" in s for s in ch["single_channel_entities"])
    top = sample_ws.incident_detail(sample_ws.incidents[0]["id"])
    assert len(top["channels"]["channels_with_evidence"]) == 6 and "channels" in top["hypothesis"]


def test_chi_square_reference():
    assert chi2_4_sf(0) == 1.0
    assert abs(chi2_4_sf(D2_REFERENCE) - 0.001) < 5e-5


def test_md_deviation_flags_attack_records_and_explains_them(sample_ws):
    devs = top_deviations(sample_ws.graph, 30)
    keyed = {(d["source"], d["target"], d["timestamp"][:16]): d for d in devs}
    bulk = keyed[("host:SRV-APP-02", "database:FINANCE-DB", "2026-10-27T21:32")]
    assert bulk["top_factor"] == "data volume" and "48,211" in bulk["explanation"] and bulk["baseline"].startswith("pair")
    assert any(d["target"] == "ip:203.0.113.45" and d["volume"] >= 400_000_000 for d in devs)
    assert all(sum(d["contributions"].values()) == pytest.approx(d["d2"], abs=0.1) for d in devs)


def test_md_deviation_alone_never_crosses_suspicion_threshold(sample_ws):
    for rel in sample_ws.graph.rels.values():
        for o in rel.occurrences:
            if o.attributes.get("suspicion_rule") == "R-SUSP-03":
                assert o.suspicion <= SUSPICION_CAP < S.suspicion_threshold
    bkp = sample_ws.graph.rels["user:svc_backup|AUTHENTICATED_TO|host:BKP-01"]
    assert max(o.attributes["deviation"]["d2"] for o in bkp.occurrences) > D2_REFERENCE
    assert bkp.max_suspicion < S.suspicion_threshold


def test_counterfactual_removes_only_prevented_occurrences(kat_ws):
    g = kat_ws.graph
    at = datetime.fromisoformat("2026-01-01T10:08:00+00:00")
    cf = counterfactual(g, ["host:SRV-01"], at)
    assert "host:WS-01|CONNECTED_TO|host:SRV-01" not in cf.rels
    assert "host:SRV-01|ACCESSED|database:DB-01" not in cf.rels
    assert cf.rels["user:user-01|AUTHENTICATED_TO|host:WS-01"] is g.rels["user:user-01|AUTHENTICATED_TO|host:WS-01"]
    assert len(g.rels) > len(cf.rels)


def test_what_if_isolating_server_protects_database(kat_ws):
    at = datetime.fromisoformat("2026-01-01T10:08:00+00:00")
    r = what_if(kat_ws.graph, "user:user-01", ["host:SRV-01"], at, S)
    assert "database:DB-01" in r["before"]["critical_assets_reachable"]
    assert "database:DB-01" in r["prevented"] and r["after"]["valid_paths"] == 0


def test_action_validation(kat_ws):
    with pytest.raises(WhatIfError):
        action_for(kat_ws.graph, "database:DB-01")
    with pytest.raises(WhatIfError):
        action_for(kat_ws.graph, "host:NOPE")
    assert action_for(kat_ws.graph, "host:WS-01")["label"] == "Isolate host WS-01"


def test_plan_at_first_alert_is_single_isolation(sample_ws):
    plan = plan_containment(sample_ws.graph, "user:sameer", T_ATTACK, S)
    assert plan["contained"]
    assert [r["action"]["target"] for r in plan["plan"]] == ["host:WS-014"]
    assert "database:FINANCE-DB" in plan["before"]["crown_jewels_suspected"]
    assert plan["after"]["crown_jewels_suspected"] == [] and plan["after"]["critical_paths"] == 0


def test_plan_after_credential_theft_needs_more_than_the_workstation(sample_ws):
    at = datetime.fromisoformat("2026-10-27T21:10:00+00:00")
    plan = plan_containment(sample_ws.graph, "user:sameer", at, S)
    held = {h["id"] for h in plan["footholds"]}
    assert {"user:svc_backup", "host:WS-014"} <= held
    targets = [r["action"]["target"] for r in plan["plan"]]
    assert plan["contained"]
    assert targets == ["host:WS-014", "user:svc_backup|AUTHENTICATED_TO|host:SRV-APP-02"]
    assert plan["pruned_as_redundant"]
    alone = what_if(sample_ws.graph, "user:sameer", ["host:WS-014"], at, S)
    assert "database:FINANCE-DB" in alone["after"]["crown_jewels_suspected"]


def test_novelty_api(deploy):
    c = TestClient(create_app(Workspace(deploy, AnalysisSettings())), raise_server_exceptions=False)
    inc = c.get("/api/incidents").json()[0]["id"]
    plan = c.get(f"/api/incidents/{inc}/containment").json()
    assert plan["contained"] and plan["plan"][0]["action"]["label"] == "Isolate host WS-014"
    later = c.get(f"/api/incidents/{inc}/containment?at=2026-10-27T21:10:00Z").json()
    assert len(later["plan"]) >= 2
    wi = c.post("/api/whatif", json={"source": "user:sameer", "actions": ["host:WS-014"], "at": "2026-10-27T20:41:00Z"})
    assert wi.status_code == 200 and "database:FINANCE-DB" in wi.json()["prevented"]
    assert c.post("/api/whatif", json={"source": "user:sameer", "actions": ["database:FINANCE-DB"]}).status_code == 422
    assert c.post("/api/whatif", json={"source": "user:sameer", "actions": []}).status_code == 422
    d = c.get("/api/deviations?limit=5").json()
    assert len(d["deviations"]) == 5 and d["suspicion_cap"] < 0.5
    rel = c.get("/api/relationships/" + quote("host:SRV-APP-02|ACCESSED|database:FINANCE-DB", safe="")).json()
    assert any(o["deviation"] and o["deviation"]["d2"] > D2_REFERENCE for o in rel["occurrences"])
    detail = c.get(f"/api/incidents/{inc}").json()
    assert detail["channels"]["agreement"] > 0.9
    assert c.get("/api/incidents/INC-9999/containment").status_code == 404
