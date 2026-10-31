"""Source adapters: map each telemetry schema into the common ``NormalizedEvent`` shape.

Every adapter declares the fields that identify its schema. Detection is by field
signature, so a renamed file is still recognised; an explicit ``source_hint`` overrides
detection. Adding a new log source means adding one adapter here — nothing downstream
changes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from .normalize import (
    NormalizationError,
    clean,
    norm_host,
    norm_ip,
    norm_process,
    norm_severity,
    norm_user,
    parse_timestamp,
    to_int,
)

Mapper = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class SourceAdapter:
    name: str  # adapter / source-system id
    label: str
    signature: frozenset[str]  # fields that must all be present
    id_field: str | None
    time_field: str
    mapper: Mapper
    is_context: bool = False  # inventory-style sources describe entities, not events


def content_id(record: dict[str, Any]) -> str:
    """Deterministic id for records that carry no id of their own."""
    blob = json.dumps(record, sort_keys=True, default=str).encode()
    return "h-" + hashlib.sha256(blob).hexdigest()[:16]


def _require(record: dict[str, Any], *fields: str) -> None:
    missing = [f for f in fields if clean(record.get(f)) is None]
    if missing:
        raise NormalizationError(f"missing required field(s): {', '.join(missing)}")


# --------------------------------------------------------------------------- mappers


def _auth(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "user", "dst_host", "result")
    result = str(r["result"]).strip().lower()
    if result not in {"success", "failure", "failed", "fail"}:
        raise NormalizationError(f"unknown authentication result {r['result']!r}")
    outcome = "success" if result == "success" else "failure"
    return {
        "category": "authentication",
        "action": f"logon:{clean(r.get('logon_type')) or 'unspecified'}",
        "outcome": outcome,
        "severity": 0.0 if outcome == "success" else 0.1,
        "user": norm_user(r.get("user")),
        "src_host": norm_host(r.get("src_host")),
        "dst_host": norm_host(r.get("dst_host")),
    }


_EDR_CATEGORY = {
    "process_start": "process",
    "network_connect": "network",
    "credential_access": "privilege",
    "service_install": "service",
}


def _edr(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "host", "event_type", "image")
    etype = str(r["event_type"]).strip().lower()
    if etype not in _EDR_CATEGORY:
        raise NormalizationError(f"unsupported EDR event_type {r['event_type']!r}")
    out: dict[str, Any] = {
        "category": _EDR_CATEGORY[etype],
        "action": etype,
        "outcome": "observed",
        "severity": norm_severity(r.get("severity")),
        "user": norm_user(r.get("user")),
        "src_host": norm_host(r.get("host")),
        "process": norm_process(r.get("image")),
        "process_id": clean(r.get("pid")),
        "parent_process": norm_process(r.get("parent_image")),
        "parent_process_id": clean(r.get("parent_pid")),
    }
    if etype == "network_connect":
        _require(r, "dst_ip")
        out["dst_ip"] = norm_ip(r.get("dst_ip"))
        if out["dst_ip"] is None:
            raise NormalizationError(f"invalid dst_ip {r.get('dst_ip')!r}")
        out["dst_port"] = to_int(r.get("dst_port"))
    elif etype == "credential_access":
        _require(r, "target_user")
        out["target_user"] = norm_user(r.get("target_user"))
    elif etype == "service_install":
        _require(r, "service_name")
        out["service"] = clean(r.get("service_name"))
    return out


def _firewall(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "src_ip", "dst_ip", "action")
    src, dst = norm_ip(r.get("src_ip")), norm_ip(r.get("dst_ip"))
    if src is None or dst is None:
        raise NormalizationError("invalid src_ip/dst_ip")
    action = str(r["action"]).strip().lower()
    if action not in {"allow", "accept", "deny", "drop", "reject"}:
        raise NormalizationError(f"unknown firewall action {r['action']!r}")
    return {
        "category": "network",
        "action": f"flow:{(clean(r.get('proto')) or 'ip').lower()}",
        "outcome": "allowed" if action in {"allow", "accept"} else "blocked",
        "severity": 0.0,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": to_int(r.get("dst_port")),
    }


def _dns(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "client_ip", "query")
    answers = r.get("answers") or []
    if isinstance(answers, str):
        answers = [a for a in answers.replace(";", ",").split(",") if a.strip()]
    first_ip = next((norm_ip(a) for a in answers if norm_ip(a)), None)
    client = norm_ip(r.get("client_ip"))
    if client is None:
        raise NormalizationError(f"invalid client_ip {r.get('client_ip')!r}")
    return {
        "category": "dns",
        "action": f"query:{(clean(r.get('qtype')) or 'A').upper()}",
        "outcome": (clean(r.get("rcode")) or "NOERROR").upper(),
        "severity": 0.0,
        "src_ip": client,
        "domain": str(r["query"]).strip().rstrip(".").lower(),
        "dst_ip": first_ip,
    }


def _db(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "client_host", "database", "operation")
    rows = to_int(r.get("rows_returned"))
    return {
        "category": "db_access",
        "action": str(r["operation"]).strip().upper(),
        "outcome": "success",
        "severity": 0.0,
        "user": norm_user(r.get("db_user")),
        "src_host": norm_host(r.get("client_host")),
        "database": norm_host(r.get("database")),
        "raw_extra": {"rows_returned": rows, "object": clean(r.get("object"))},
    }


def _alert(r: dict[str, Any]) -> dict[str, Any]:
    _require(r, "rule_name", "severity")
    ents = r.get("entities") or {}
    if not isinstance(ents, dict):
        raise NormalizationError("alert 'entities' must be an object")
    named: list[str] = []
    for u in ents.get("users", []) or []:
        if norm_user(u):
            named.append(f"user:{norm_user(u)}")
    for h in ents.get("hosts", []) or []:
        if norm_host(h):
            named.append(f"host:{norm_host(h)}")
    for ip in ents.get("ips", []) or []:
        if norm_ip(ip):
            named.append(f"ip:{norm_ip(ip)}")
    for d in ents.get("databases", []) or []:
        if norm_host(d):
            named.append(f"database:{norm_host(d)}")
    refs = r.get("evidence_refs") or []
    if not isinstance(refs, list):
        raise NormalizationError("alert 'evidence_refs' must be a list")
    return {
        "category": "alert",
        "action": "detection",
        "outcome": (clean(r.get("status")) or "open").lower(),
        "severity": norm_severity(r.get("severity")),
        "alert_name": str(r["rule_name"]).strip(),
        "technique": clean(r.get("mitre")),
        "disposition": (clean(r.get("disposition")) or "undetermined").lower(),
        "related_event_ids": [str(x).strip() for x in refs if clean(x)],
        "alert_entities": sorted(set(named)),
    }


def _normalized(r: dict[str, Any]) -> dict[str, Any]:
    """Pass-through for files already in the common schema (custom integrations)."""
    _require(r, "category")
    out: dict[str, Any] = {
        "category": str(r["category"]).strip().lower(),
        "action": clean(r.get("action")) or "",
        "outcome": clean(r.get("outcome")) or "",
        "severity": norm_severity(r.get("severity")),
        "user": norm_user(r.get("user")),
        "target_user": norm_user(r.get("target_user")),
        "src_host": norm_host(r.get("src_host")),
        "dst_host": norm_host(r.get("dst_host")),
        "src_ip": norm_ip(r.get("src_ip")),
        "dst_ip": norm_ip(r.get("dst_ip")),
        "dst_port": to_int(r.get("dst_port")),
        "process": norm_process(r.get("process")),
        "process_id": clean(r.get("process_id")),
        "parent_process": norm_process(r.get("parent_process")),
        "parent_process_id": clean(r.get("parent_process_id")),
        "database": norm_host(r.get("database")),
        "service": clean(r.get("service")),
        "domain": (clean(r.get("domain")) or "").lower() or None,
    }
    allowed = {"authentication", "process", "network", "dns", "db_access", "privilege", "service"}
    if out["category"] not in allowed:
        raise NormalizationError(f"category must be one of {sorted(allowed)}")
    return out


def _inventory(r: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - handled by loader
    return {}


ADAPTERS: list[SourceAdapter] = [
    SourceAdapter(
        "idp_auth", "Identity provider / Windows authentication log",
        frozenset({"user", "dst_host", "result", "logon_type"}), "event_id", "time", _auth,
    ),
    SourceAdapter(
        "edr", "Endpoint detection & response telemetry",
        frozenset({"host", "event_type", "image"}), "id", "ts", _edr,
    ),
    SourceAdapter(
        "firewall", "Perimeter / internal firewall flow log",
        frozenset({"src_ip", "dst_ip", "action", "proto"}), "log_id", "timestamp", _firewall,
    ),
    SourceAdapter(
        "dns", "DNS resolver query log",
        frozenset({"client_ip", "query"}), "qid", "time", _dns,
    ),
    SourceAdapter(
        "db_audit", "Database audit log",
        frozenset({"client_host", "database", "operation"}), "audit_id", "event_time", _db,
    ),
    SourceAdapter(
        "siem_alerts", "SIEM detection alerts",
        frozenset({"rule_name", "severity", "entities"}), "alert_id", "created", _alert,
    ),
    SourceAdapter(
        "asset_inventory", "Asset / identity inventory (context)",
        frozenset({"asset_id", "asset_type", "name", "criticality"}), "asset_id", "", _inventory, is_context=True,
    ),
    SourceAdapter(
        "normalized", "AttackGraph Lens common event schema",
        frozenset({"event_id", "timestamp", "source_system", "category"}), "event_id", "timestamp", _normalized,
    ),
]

ADAPTERS_BY_NAME = {a.name: a for a in ADAPTERS}


def detect_adapter(fields: set[str], hint: str | None = None) -> SourceAdapter | None:
    if hint:
        return ADAPTERS_BY_NAME.get(hint)
    # Most specific signature first so a superset schema is not mis-detected.
    for adapter in sorted(ADAPTERS, key=lambda a: -len(a.signature)):
        if adapter.signature <= fields:
            return adapter
    return None


def map_record(adapter: SourceAdapter, record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Map one raw record. Returns ``(fields, notes)``; raises ``NormalizationError``."""
    ts, note = parse_timestamp(record.get(adapter.time_field))
    fields = adapter.mapper(record)
    fields.pop("raw_extra", None)  # original record is preserved verbatim by the loader
    notes = [note] if note else []
    raw_id = clean(record.get(adapter.id_field)) if adapter.id_field else None
    fields["event_id"] = raw_id or content_id(record)
    if raw_id is None:
        notes.append("record had no event id; deterministic content hash assigned")
    fields["timestamp"] = ts
    if adapter.name == "normalized":
        fields["source_system"] = clean(record.get("source_system")) or "normalized"
    else:
        fields["source_system"] = adapter.name
    return fields, notes
