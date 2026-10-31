"""Entity extraction, de-duplication, relationship creation, provenance and temporal ordering."""
from attackgraph.models import Basis, EntityType, RelType


def rel(ws, s, t, typ):
    return ws.graph.rels.get(f"{s}|{typ}|{t}")


def test_entities_extracted_and_deduplicated(kat_ws):
    g = kat_ws.graph
    # "USER-01", "user-01" and "CORP\\USER-01" are one identity
    assert [e for e in g.entities if e.startswith("user:user-01")] == ["user:user-01"]
    # "ws-01.corp.local" and "WS-01" are one host
    assert "host:WS-01" in g.entities and not any("corp" in e.lower() for e in g.entities)
    assert g.entities["database:DB-01"].type == EntityType.DATABASE
    assert g.entities["database:DB-01"].criticality == 5  # from inventory
    assert g.entities["host:SRV-01"].in_inventory


def test_relationships_and_provenance(kat_ws):
    r = rel(kat_ws, "user:user-01", "host:WS-01", "AUTHENTICATED_TO")
    assert r is not None and len(r.occurrences) == 2  # E1 + E9 aggregated on one relationship
    assert [o.event_uid for o in r.occurrences] == ["idp:E1", "idp:E9"]
    o = r.occurrences[0]
    assert o.rule == "R-AUTH-01" and o.source_system == "idp" and o.basis == Basis.OBSERVED
    ev = kat_ws.graph.events[o.event_uid]
    assert ev.source_file == "kat_events.csv" and ev.source_row == 2
    assert rel(kat_ws, "host:WS-01", "process:WS-01/evil.exe#100", "EXECUTED") is not None
    assert rel(kat_ws, "host:SRV-01", "database:DB-01", "ACCESSED").occurrences[0].event_uid == "dbaudit:E4"


def test_ip_resolution_is_marked_inferred(kat_ws):
    r = rel(kat_ws, "host:WS-01", "host:SRV-01", "CONNECTED_TO")
    assert r is not None and r.basis == Basis.INFERRED and r.occurrences[0].rule == "R-NET-02"


def test_failed_logons_and_blocked_flows_create_no_edges(kat_ws):
    g = kat_ws.graph
    assert "user:user-99" in g.entities and "host:WS-99" in g.entities  # disconnected nodes kept
    assert g.g.degree("user:user-99") == 0 and g.g.degree("host:WS-99") == 0
    assert rel(kat_ws, "host:WS-01", "database:DB-01", "CONNECTED_TO") is None  # E10 was blocked
    assert "netflow:E10" in g.entity_events["host:WS-01"]  # ...but the record is still evidence for the entity


def test_cycles_are_represented(kat_ws):
    assert rel(kat_ws, "host:WS-01", "host:SRV-01", "CONNECTED_TO")
    assert rel(kat_ws, "host:SRV-01", "host:WS-01", "CONNECTED_TO")


def test_occurrences_are_time_ordered(kat_ws):
    for r in kat_ws.graph.rels.values():
        ts = [o.timestamp for o in r.occurrences]
        assert ts == sorted(ts)


def test_every_occurrence_traces_to_an_event_and_rule(sample_ws):
    from attackgraph.rules import RULES
    g = sample_ws.graph
    for r in g.rels.values():
        assert r.type in RelType
        for o in r.occurrences:
            assert o.event_uid in g.events
            assert o.rule in RULES


def test_empty_dataset(deploy):
    from attackgraph.workspace import Workspace
    ws = Workspace(deploy)
    s = ws.summary()
    assert s["events"] == 0 and s["entities"] == 0 and s["incidents"] == 0 and s["top_incident"] is None
