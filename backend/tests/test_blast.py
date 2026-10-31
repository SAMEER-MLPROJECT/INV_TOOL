"""Blast-radius accuracy, hop limits and evidence tiers."""
from datetime import datetime, timezone

import pytest

from attackgraph.config import AnalysisSettings
from attackgraph.graph.blast import BlastError, compute_blast_radius

S = AnalysisSettings()


def ids(res):
    return {n["id"]: n for n in res["nodes"]}


def test_structural_blast_radius_uses_shortest_hop(kat_ws):
    g = kat_ws.graph
    three = ids(compute_blast_radius(g, "user:user-01", S, max_hops=3, temporal=False))
    two = ids(compute_blast_radius(g, "user:user-01", S, max_hops=2, temporal=False))
    assert "database:DB-01" in two  # structurally via WS-02 (2 hops) ...
    assert two["database:DB-01"]["hop"] == 2
    assert three["database:DB-01"]["hop"] == 2


def test_temporal_mode_uses_only_time_respecting_routes(kat_ws):
    g = kat_ws.graph
    since = datetime(2026, 1, 1, 9, 45, tzinfo=timezone.utc)  # after the 09:00 WS-02 DB access
    res = ids(compute_blast_radius(g, "user:user-01", S, max_hops=3, temporal=True, since=since))
    # WS-02's DB access happened before compromise time, so DB-01 is only reachable via WS-01 -> SRV-01 (3 hops)
    assert res["database:DB-01"]["hop"] == 3
    assert [r.split("|")[1] for r in res["database:DB-01"]["via"]] == ["AUTHENTICATED_TO", "CONNECTED_TO", "ACCESSED"]
    assert res["database:DB-01"]["earliest_arrival"].startswith("2026-01-01T10:20")
    res2 = ids(compute_blast_radius(g, "user:user-01", S, max_hops=2, temporal=True, since=since))
    assert "database:DB-01" not in res2  # hop limit enforced


def test_hop_validation(kat_ws):
    for bad in (0, 9):
        with pytest.raises(BlastError):
            compute_blast_radius(kat_ws.graph, "user:user-01", S, max_hops=bad)
    with pytest.raises(BlastError):
        compute_blast_radius(kat_ws.graph, "user:nobody", S)


def test_evidence_tiers_and_analyst_confirmation(kat_ws):
    g = kat_ws.graph
    res = ids(compute_blast_radius(g, "user:user-01", S, max_hops=3, temporal=False))
    # user-01 -> WS-01 carries severity 0.8 (E1), WS-01 -> evil.exe carries 0.9: an unbroken suspicious chain
    assert res["host:WS-01"]["classification"] == "SUSPECTED_LATERAL_MOVEMENT"
    assert res["process:WS-01/evil.exe#100"]["classification"] == "SUSPECTED_LATERAL_MOVEMENT"
    assert res["host:WS-02"]["classification"] == "OBSERVED_CONNECTION"
    assert res["host:SRV-01"]["classification"] == "POTENTIAL_EXPOSURE"  # reached by an unsuspicious hop
    assert all(n["classification"] != "CONFIRMED_COMPROMISE" for n in res.values())  # never automatic
    res2 = ids(compute_blast_radius(g, "user:user-01", S, max_hops=3, temporal=False, statuses={"host:SRV-01": "confirmed"}))
    assert res2["host:SRV-01"]["classification"] == "CONFIRMED_COMPROMISE"


def test_growth_curve_is_cumulative(sample_ws):
    res = compute_blast_radius(sample_ws.graph, "user:sameer", S, max_hops=4)
    counts = [x["reachable"] for x in res["growth"]]
    assert counts == sorted(counts) and len(counts) == 8
    assert counts[3] == res["summary"]["reachable"]
