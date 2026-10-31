from datetime import datetime, timezone

import pytest

from attackgraph.config import AnalysisSettings
from attackgraph.graph.paths import PathError, PathQuery, find_paths
from attackgraph.models import RelType

S = AnalysisSettings()


def test_known_answer_path_user_ws_srv_db(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=5), S)
    nodes = [p["nodes"] for p in res["paths"]]
    assert ["user:user-01", "host:WS-01", "host:SRV-01", "database:DB-01"] in nodes
    p = next(p for p in res["paths"] if p["nodes"] == ["user:user-01", "host:WS-01", "host:SRV-01", "database:DB-01"])
    times = [s["timestamp"] for s in p["steps"]]
    assert times == sorted(times)
    assert [s["event_uid"] for s in p["steps"]] == ["idp:E1", "netflow:E3", "dbaudit:E4"]
    assert p["temporally_consistent"] and 0 <= p["score"] <= 100
    assert {b["component"] for b in p["breakdown"]} == {"criticality", "suspicion", "corroboration", "evidence_quality", "path_length", "recency"}
    assert abs(sum(b["contribution"] for b in p["breakdown"]) - p["score"]) < 0.2


def test_temporally_impossible_path_is_rejected_with_reason(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=5), S)
    assert all("host:WS-02" not in p["nodes"] for p in res["paths"])
    rej = [r for r in res["rejected_temporally_impossible"] if r["nodes"] == ["user:user-01", "host:WS-02", "database:DB-01"]]
    assert rej and "before the earliest possible arrival" in rej[0]["reason"]


def test_hop_limit_enforced(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=2), S)
    assert res["paths"] == []
    for bad in (0, 9):
        with pytest.raises(PathError):
            find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=bad), S)


def test_relationship_filter(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=5,
                                             rel_types={RelType.AUTHENTICATED_TO, RelType.ACCESSED}), S)
    assert res["paths"] == []


def test_since_excludes_earlier_activity(kat_ws):
    since = datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc)
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=5, since=since), S)
    assert res["paths"] == []


def test_cycles_do_not_loop(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("host:WS-01", ["host:SRV-01"], max_hops=8), S)
    for p in res["paths"]:
        assert len(p["nodes"]) == len(set(p["nodes"]))


def test_unknown_entities_raise(kat_ws):
    with pytest.raises(PathError):
        find_paths(kat_ws.graph, PathQuery("user:ghost"), S)
    with pytest.raises(PathError):
        find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:NOPE"]), S)


def test_auto_targets_are_critical_assets(kat_ws):
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", None, max_hops=5), S)
    assert set(res["targets"]) == {"host:SRV-01", "database:DB-01"}


def test_search_budget_marks_truncation(sample_ws):
    tight = AnalysisSettings()
    tight.search_budget = 50
    res = find_paths(sample_ws.graph, PathQuery("user:sameer", None, max_hops=8), tight)
    assert res["search"]["expansions"] <= 51 and res["search"]["truncated"] is True


def test_max_gap_between_steps(kat_ws):
    s = AnalysisSettings(max_hop_gap_hours=5 / 60)
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["host:SRV-01"], max_hops=5), s)
    assert res["paths"] == []
    ok = find_paths(kat_ws.graph, PathQuery("user:user-01", ["host:SRV-01"], max_hops=5), AnalysisSettings(max_hop_gap_hours=0.25))
    assert ok["paths"]
    assert any("max gap" in r["reason"] for r in res["rejected_temporally_impossible"])


def test_candidate_provider_results_are_temporally_validated(kat_ws):
    good = ["user:user-01|AUTHENTICATED_TO|host:WS-01", "host:WS-01|CONNECTED_TO|host:SRV-01", "host:SRV-01|ACCESSED|database:DB-01"]
    bad = ["user:user-01|AUTHENTICATED_TO|host:WS-02", "host:WS-02|ACCESSED|database:DB-01"]
    res = find_paths(kat_ws.graph, PathQuery("user:user-01", ["database:DB-01"], max_hops=5), S,
                     candidate_provider=lambda s, t, h: [good, bad])
    assert [p["nodes"][-2] for p in res["paths"]] == ["host:SRV-01"]
    assert res["rejected_temporally_impossible"][0]["nodes"][1] == "host:WS-02"
    assert res["search"]["engine"].startswith("Neo4j")
