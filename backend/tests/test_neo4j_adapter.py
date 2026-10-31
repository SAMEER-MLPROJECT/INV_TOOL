import pytest

from attackgraph.store.neo4j_store import Neo4jGraphStore, Neo4jUnavailable


class FakeSession:
    def __init__(self, log, responder):
        self.log, self.responder = log, responder

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, params):
        self.log.append((query, params))
        return self.responder(query, params)


class FakeDriver:
    def __init__(self, responder=lambda q, p: []):
        self.log = []
        self.responder = responder
        self.closed = False

    def session(self, database):
        assert database == "neo4j"
        return FakeSession(self.log, self.responder)

    def verify_connectivity(self):
        return None

    def close(self):
        self.closed = True


def make(responder=lambda q, p: []):
    drv = FakeDriver(responder)
    store = Neo4jGraphStore("neo4j+s://example.databases.neo4j.io", "neo4j", "pw", driver_factory=lambda *a: drv)
    return store, drv


def test_requires_credentials():
    with pytest.raises(Neo4jUnavailable):
        Neo4jGraphStore("", "", "")


def test_sync_is_batched_and_parameterised(kat_ws):
    store, drv = make()
    res = store.sync(kat_ws.graph)
    assert res == {"nodes": len(kat_ws.graph.entities), "relationships": len(kat_ws.graph.rels)}
    queries = [q for q, _ in drv.log]
    assert queries[0] == "MATCH (n:Entity) DETACH DELETE n"
    assert any("CREATE CONSTRAINT entity_id" in q for q in queries)
    unwinds = [(q, p) for q, p in drv.log if q.startswith("UNWIND $rows")]
    assert unwinds and all("rows" in p for _, p in unwinds)
    for q, _ in drv.log:
        assert "user-01" not in q and "DB-01" not in q
    rel_rows = [r for q, p in unwinds if "MERGE (a)-[r:" in q for r in p["rows"]]
    accessed = next(r for r in rel_rows if r["id"] == "host:SRV-01|ACCESSED|database:DB-01")
    assert accessed["events"] == ["dbaudit:E4"] and accessed["traversable"] is True


def test_injection_attempt_stays_in_parameters():
    store, drv = make(lambda q, p: [{"rels": ["a|X|b"]}])
    evil = "x'}) MATCH (n) DETACH DELETE n //"
    store.candidate_paths(evil, "database:DB-01", 3)
    q, p = drv.log[-1]
    assert evil not in q and p["source"] == evil
    assert "*1..3" in q


@pytest.mark.parametrize("bad", [0, 9, "3; DROP", 2.5])
def test_hop_bound_validated(bad):
    store, _ = make()
    with pytest.raises(ValueError):
        store.candidate_paths("a", "b", bad)


def test_workspace_sync_and_neo4j_backed_path_search(kat_ws):
    good = ["user:user-01|AUTHENTICATED_TO|host:WS-01", "host:WS-01|CONNECTED_TO|host:SRV-01", "host:SRV-01|ACCESSED|database:DB-01"]

    def responder(q, p):
        if "dbms.components" in q:
            return [{"name": "Neo4j Kernel", "versions": ["5.x"], "edition": "fake"}]
        if q.startswith("MATCH p ="):
            return [{"rels": good}]
        return []

    drv = FakeDriver(responder)
    kat_ws.deploy.neo4j_uri, kat_ws.deploy.neo4j_user, kat_ws.deploy.neo4j_password = "neo4j://x", "u", "p"
    kat_ws.deploy.graph_backend = "neo4j"
    status = kat_ws.neo4j_connect_and_sync(factory=lambda *a: drv)
    assert status["neo4j"]["synced"] and status["neo4j"]["uri_host"] == "x"
    from attackgraph.graph.paths import PathQuery
    res = kat_ws.paths(PathQuery("user:user-01", ["database:DB-01"], max_hops=4))
    assert res["search"]["engine"].startswith("Neo4j") and res["paths"][0]["nodes"][-1] == "database:DB-01"


def test_connection_failure_reports_class_not_secret(kat_ws):
    def factory(*a):
        raise ConnectionError("password=hunter2 refused")
    kat_ws.deploy.neo4j_uri, kat_ws.deploy.neo4j_user, kat_ws.deploy.neo4j_password = "neo4j://x", "u", "hunter2"
    status = kat_ws.neo4j_connect_and_sync(factory=factory)
    assert not status["neo4j"]["synced"] and "hunter2" not in str(status) and "ConnectionError" in status["neo4j"]["message"]
