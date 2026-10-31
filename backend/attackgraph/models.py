from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    PROCESS = "process"
    DATABASE = "database"
    SERVICE = "service"
    DOMAIN = "domain"
    ALERT = "alert"


class RelType(str, Enum):
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    EXECUTED = "EXECUTED"
    SPAWNED = "SPAWNED"
    CONNECTED_TO = "CONNECTED_TO"
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    ACCESSED = "ACCESSED"
    QUERIED = "QUERIED"
    RESOLVED_TO = "RESOLVED_TO"
    MODIFIED = "MODIFIED"
    PRIVILEGE_ESCALATED = "PRIVILEGE_ESCALATED"
    ALERTED_ON = "ALERTED_ON"


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

    OBSERVED = "observed"
    INFERRED = "inferred"


class NormalizedEvent(BaseModel):
    uid: str
    event_id: str
    timestamp: datetime
    source_system: str
    source_file: str
    source_row: int
    category: str
    action: str = ""
    outcome: str = ""
    severity: float = 0.0
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
    alert_entities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class Entity(BaseModel):
    id: str
    type: EntityType
    name: str
    category: str = ""
    criticality: int = 1
    in_inventory: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Occurrence(BaseModel):
    event_uid: str
    timestamp: datetime
    source_system: str
    basis: Basis
    rule: str
    suspicion: float = 0.0
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    id: str
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
    level: str
    message: str
