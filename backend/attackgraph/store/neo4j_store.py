"""Neo4j persistence and query adapter (optional backend; works with Neo4j AuraDB or self-hosted).

Design
------
* Every entity is a node labelled ``:Entity`` plus one label for its type (``:User``,
  ``:Host``...). Relationships keep their semantic type (``:AUTHENTICATED_TO``...) and carry
  occurrence arrays: timestamps, event uids, source systems, suspicion and basis.
* All *values* are passed as query parameters. Labels and relationship types cannot be
  parameterised in Cypher, so they are taken only from the fixed ``EntityType`` /
  ``RelType`` enumerations (never from user input). Variable-length hop bounds are
  validated integers in a fixed range.
* Neo4j generates structural path candidates and hop-bounded neighbourhoods; the
  temporal-consistency check and ranking are applied by the same Python engine that the
  local mode uses, so results are identical in both modes.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from ..graph.builder import TemporalGraph
from ..models import TRAVERSABLE, EntityType, RelType

log = logging.getLogger(__name__)

LABELS = {t: t.value.capitalize() for t in EntityType}
BATCH = 500


class Neo4jUnavailable(RuntimeError):
    pass


def _default_driver_factory(uri: str, user: str, password: str):  # pragma: no cover - needs a live server
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise Neo4jUnavailable("the 'neo4j' Python driver is not installed") from exc
    return GraphDatabase.driver(uri, auth=(user, password), connection_timeout=10)


class Neo4jGraphStore:
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j",
                 driver_factory: Callable[[str, str, str], Any] | None = None) -> None:
        if not (uri and user and password):
            raise Neo4jUnavailable("NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD must all be set")
        self.uri = uri
        self.database = database
        self._driver = (driver_factory or _default_driver_factory)(uri, user, password)

    # ----------------------------------------------------------------- plumbing
    def _run(self, query: str, **params: Any) -> list[dict]:
        with self._driver.session(database=self.database) as session:
            result = session.run(query, params)
            return [dict(r) for r in result]

    def close(self) -> None:
        self._driver.close()

    def verify(self) -> dict:
        self._driver.verify_connectivity()
        rows = self._run("CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition")
        return rows[0] if rows else {}

    # ------------------------------------------------------------------- schema
    def ensure_schema(self) -> list[str]:
        statements = [
            "CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE",
            "CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.type)",
            "CREATE INDEX entity_criticality IF NOT EXISTS FOR (e:Entity) ON (e.criticality)",
        ]
        for s in statements:
            self._run(s)
        return statements

    # --------------------------------------------------------------------- sync
    def sync(self, g: TemporalGraph, clear: bool = True) -> dict:
        if clear:
            self._run("MATCH (n:Entity) DETACH DELETE n")
        self.ensure_schema()
        by_type: dict[EntityType, list[dict]] = {}
        for e in g.entities.values():
            by_type.setdefault(e.type, []).append({
                "id": e.id, "name": e.name, "type": e.type.value, "category": e.category,
                "criticality": e.criticality, "in_inventory": e.in_inventory,
                "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                "last_seen": e.last_seen.isoformat() if e.last_seen else None,
            })
        nodes = 0
        for etype, rows in by_type.items():
            label = LABELS[etype]  # enum-derived, safe to interpolate
            for i in range(0, len(rows), BATCH):
                chunk = rows[i:i + BATCH]
                self._run(f"UNWIND $rows AS row MERGE (e:Entity {{id: row.id}}) SET e += row, e:{label}", rows=chunk)
                nodes += len(chunk)
        by_rel: dict[RelType, list[dict]] = {}
        for r in g.rels.values():
            by_rel.setdefault(r.type, []).append({
                "id": r.id, "src": r.source, "dst": r.target,
                "times": [o.timestamp.isoformat() for o in r.occurrences],
                "events": [o.event_uid for o in r.occurrences],
                "sources": sorted(r.sources), "max_suspicion": r.max_suspicion,
                "basis": r.basis.value, "count": len(r.occurrences),
                "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
                "traversable": r.type in TRAVERSABLE,
            })
        rels = 0
        for rtype, rows in by_rel.items():
            for i in range(0, len(rows), BATCH):
                chunk = rows[i:i + BATCH]
                self._run(
                    f"UNWIND $rows AS row MATCH (a:Entity {{id: row.src}}) MATCH (b:Entity {{id: row.dst}}) "
                    f"MERGE (a)-[r:{rtype.value} {{id: row.id}}]->(b) "
                    "SET r.times = row.times, r.events = row.events, r.sources = row.sources, "
                    "r.max_suspicion = row.max_suspicion, r.basis = row.basis, r.count = row.count, "
                    "r.first_seen = row.first_seen, r.last_seen = row.last_seen, r.traversable = row.traversable",
                    rows=chunk,
                )
                rels += len(chunk)
        return {"nodes": nodes, "relationships": rels}

    # ------------------------------------------------------------------ queries
    @staticmethod
    def _hops(max_hops: int) -> int:
        if not isinstance(max_hops, int) or not 1 <= max_hops <= 8:
            raise ValueError("max_hops must be an integer between 1 and 8")
        return max_hops

    def candidate_paths(self, source: str, target: str, max_hops: int, limit: int = 200) -> list[list[str]]:
        """Structural simple paths source -> target over traversable relationships (relationship ids)."""
        hops = self._hops(max_hops)
        rows = self._run(
            f"MATCH p = (s:Entity {{id: $source}})-[*1..{hops}]->(t:Entity {{id: $target}}) "
            "WHERE all(r IN relationships(p) WHERE r.traversable) "
            "AND all(i IN range(0, size(nodes(p)) - 2) WHERE NOT nodes(p)[i] IN nodes(p)[i + 1..]) "
            "RETURN [r IN relationships(p) | r.id] AS rels LIMIT $limit",
            source=source, target=target, limit=int(limit),
        )
        return [r["rels"] for r in rows]

    def neighbourhood_counts(self, source: str, max_hops: int) -> dict[str, int]:
        hops = self._hops(max_hops)
        rows = self._run(
            f"MATCH (s:Entity {{id: $source}})-[rs*1..{hops}]->(n:Entity) "
            "WHERE all(r IN rs WHERE r.traversable) AND n.id <> $source "
            "RETURN n.type AS type, count(DISTINCT n) AS n",
            source=source,
        )
        return {r["type"]: r["n"] for r in rows}

    def counts(self) -> dict:
        rows = self._run("MATCH (n:Entity) WITH count(n) AS nodes "
                         "OPTIONAL MATCH ()-[r]->() RETURN nodes, count(r) AS relationships")
        return rows[0] if rows else {"nodes": 0, "relationships": 0}
