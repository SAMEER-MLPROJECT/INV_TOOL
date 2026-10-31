"""Core data model shared by every pipeline stage.

The model separates three things that are easy to conflate in security tooling:

* ``NormalizedEvent`` — one record as it appeared in a source file, mapped into a
  common shape but still pointing back to the exact file/row it came from.
* ``Entity`` — a real-world thing (user, host, process, database...) referenced by events.
* ``Relationship`` — a directed, typed edge between two entities that aggregates every
  occurrence (event) that supports it, each with its own timestamp and provenance.

A relationship is evidence of *interaction*, never evidence of compromise.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    USER = "user"
    HOST = "host"  # workstation or server (see ``Entity.category``)
    IP = "ip"
    PROCESS = "process"
    DATABASE = "database"
    SERVICE = "service"
    DOMAIN = "domain"
    ALERT = "alert"


class RelType(str, Enum):
    AUTHENTICATED_TO = "AUTHENTICATED_TO"  # user -> host (successful logon)
    EXECUTED = "EXECUTED"  # host -> process (process ran on host)
    SPAWNED = "SPAWNED"  # process -> child process
    CONNECTED_TO = "CONNECTED_TO"  # host/process -> host/ip (internal network connection)
    COMMUNICATED_WITH = "COMMUNICATED_WITH"  # host/process -> external ip (egress)
    ACCESSED = "ACCESSED"  # host -> database (database session / query)
    QUERIED = "QUERIED"  # host -> domain (DNS lookup)
    RESOLVED_TO = "RESOLVED_TO"  # domain -> ip (DNS answer)
    MODIFIED = "MODIFIED"  # process -> service (installed / changed)
    PRIVILEGE_ESCALATED = "PRIVILEGE_ESCALATED"  # process -> user (credential / token obtained)
    ALERTED_ON = "ALERTED_ON"  # alert -> entity (detection context)


# Relationship types that represent a capability an adversary could traverse.
# Context edges (inventory, alerts) are kept for explanation but never walked.
TRAVERSABLE: frozenset[RelType] = frozenset(
    {
        RelType.AUTHENTICATED_TO,
        RelType.EXECUTED,
        RelType.SPAWNED,
        RelType.CONNECTED_TO,
        RelType.COMMUNICATED_WITH,
        RelType.ACCESSED,
        RelType.QUERIED,
        RelType.RESOLVED_TO,
        RelType.MODIFIED,
        RelType.PRIVILEGE_ESCALATED,
    }
)


class Basis(str, Enum):
    """How a relationship occurrence was established."""

    OBSERVED = "observed"  # both endpoints named explicitly in the source record
    INFERRED = "inferred"  # at least one endpoint resolved through a documented rule


class NormalizedEvent(BaseModel):
    uid: str  # globally unique: "<source_system>:<event_id>"
    event_id: str  # id as it appears in the source (or a deterministic content hash)
    timestamp: datetime  # always timezone-aware UTC
    source_system: str  # e.g. "idp_auth", "edr", "firewall"
    source_file: str
    source_row: int  # 1-based row/line/array index inside the source file
    category: str  # authentication | process | network | dns | db_access | privilege | service | alert
    action: str = ""
    outcome: str = ""
    severity: float = 0.0  # 0..1, native severity mapped by the adapter
    user: str | None = None
    target_user: str | None = None
    src_host: str | None = None
    dst_host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    process: str | None = None
    process_id: str | None = None
    parent_process: str | None = None
    parent_process_id: str | None = None
    database: str | None = None
    service: str | None = None
    domain: str | None = None
    alert_name: str | None = None
    technique: str | None = None
    disposition: str | None = None
    related_event_ids: list[str] = Field(default_factory=list)
    alert_entities: list[str] = Field(default_factory=list)  # canonical entity ids named by an alert
    notes: list[str] = Field(default_factory=list)  # normalization notes (e.g. "timezone assumed UTC")
    raw: dict[str, Any] = Field(default_factory=dict)


class Entity(BaseModel):
    id: str  # canonical "<type>:<name>"
    type: EntityType
    name: str
    category: str = ""  # workstation | server | domain_controller | external | ...
    criticality: int = 1  # 1 (low) .. 5 (crown jewel)
    in_inventory: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Occurrence(BaseModel):
    event_uid: str
    timestamp: datetime
    source_system: str
    basis: Basis
    rule: str  # id of the mapping/inference rule that produced this occurrence
    suspicion: float = 0.0  # 0..1 suspicion carried by this specific record
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    id: str  # "<src>|<TYPE>|<dst>"
    source: str
    target: str
    type: RelType
    occurrences: list[Occurrence] = Field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return self.occurrences[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.occurrences[-1].timestamp

    @property
    def basis(self) -> Basis:
        return Basis.OBSERVED if any(o.basis == Basis.OBSERVED for o in self.occurrences) else Basis.INFERRED

    @property
    def max_suspicion(self) -> float:
        return max((o.suspicion for o in self.occurrences), default=0.0)

    @property
    def sources(self) -> set[str]:
        return {o.source_system for o in self.occurrences}


class IngestIssue(BaseModel):
    source_file: str
    source_row: int | None
    level: str  # "error" (record rejected) | "warning" (record kept, flagged) | "conflict" | "duplicate"
    message: str
