from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import IngestIssue, NormalizedEvent
from .normalize import NormalizationError, clean, norm_host, norm_ip, norm_user, to_int
from .sources import ADAPTERS_BY_NAME, SourceAdapter, detect_adapter, map_record

ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson"}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_ISSUES_PER_FILE = 500


class IngestError(ValueError):
    pass


def sanitize_filename(name: str) -> str:
    base = Path(str(name).replace("\\", "/")).name
    base = _SAFE_NAME.sub("_", base).lstrip(".")
    if not base:
        raise IngestError("empty file name")
    return base[:120]


@dataclass
class InventoryItem:
    asset_id: str
    asset_type: str
    name: str
    ip: str | None
    criticality: int
    owner: str | None
    tags: list[str]
    source_file: str
    source_row: int


@dataclass
class FileResult:
    file_name: str
    sha256: str
    size_bytes: int
    adapter: str | None
    adapter_label: str | None
    records_read: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    conflicts: int = 0
    warnings: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None
    issues: list[IngestIssue] = field(default_factory=list)
    events: list[NormalizedEvent] = field(default_factory=list)
    inventory: list[InventoryItem] = field(default_factory=list)
    loaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_issue(self, row: int | None, level: str, message: str) -> None:
        if len(self.issues) < MAX_ISSUES_PER_FILE:
            self.issues.append(IngestIssue(source_file=self.file_name, source_row=row, level=level, message=message))

    def summary(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_system": self.adapter,
            "source_label": self.adapter_label,
            "records_read": self.records_read,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "conflicts": self.conflicts,
            "warnings": self.warnings,
            "first_event": self.first_event.isoformat() if self.first_event else None,
            "last_event": self.last_event.isoformat() if self.last_event else None,
            "loaded_at": self.loaded_at.isoformat(),
            "issues": [i.model_dump() for i in self.issues],
        }


def _records(name: str, text: str, max_records: int) -> list[Any]:
    ext = Path(name).suffix.lower()
    if ext == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise IngestError("CSV file has no header row")
        rows: list[Any] = []
        for row in reader:
            if len(rows) >= max_records:
                raise IngestError(f"file exceeds the {max_records} record limit")
            rows.append({k.strip(): v for k, v in row.items() if k is not None})
        return rows
    if ext in {".jsonl", ".ndjson"}:
        out: list[Any] = []
        for i, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            if len(out) >= max_records:
                raise IngestError(f"file exceeds the {max_records} record limit")
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append(_Unparseable(i))
        return out
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid JSON at line {exc.lineno}") from exc
    if isinstance(doc, dict):
        for key in ("records", "events", "alerts", "data"):
            if isinstance(doc.get(key), list):
                doc = doc[key]
                break
        else:
            doc = [doc]
    if not isinstance(doc, list):
        raise IngestError("JSON must be an array of records or an object with a 'records' array")
    if len(doc) > max_records:
        raise IngestError(f"file exceeds the {max_records} record limit")
    return doc


@dataclass
class _Unparseable:
    line: int


def _inventory_item(rec: dict[str, Any], file_name: str, row: int) -> InventoryItem:
    for f in ("asset_id", "asset_type", "name", "criticality"):
        if clean(rec.get(f)) is None:
            raise NormalizationError(f"missing required field: {f}")
    crit = to_int(rec.get("criticality"))
    if crit is None or not 1 <= crit <= 5:
        raise NormalizationError("criticality must be an integer 1-5")
    atype = str(rec["asset_type"]).strip().lower()
    valid = {"workstation", "server", "domain_controller", "database", "user", "service_account", "admin_account", "network_device"}
    if atype not in valid:
        raise NormalizationError(f"unknown asset_type {atype!r}")
    ip = norm_ip(rec.get("ip"))
    if clean(rec.get("ip")) and ip is None:
        raise NormalizationError(f"invalid ip {rec.get('ip')!r}")
    name = norm_user(rec["name"]) if atype in {"user", "service_account", "admin_account"} else norm_host(rec["name"])
    tags = [t.strip() for t in str(rec.get("tags") or "").split(";") if t.strip()]
    return InventoryItem(
        asset_id=str(rec["asset_id"]).strip(), asset_type=atype, name=name or "", ip=ip, criticality=crit,
        owner=clean(rec.get("owner")), tags=tags, source_file=file_name, source_row=row,
    )


def ingest_bytes(
    data: bytes,
    file_name: str,
    *,
    max_bytes: int,
    max_records: int,
    source_hint: str | None = None,
) -> FileResult:
    safe = sanitize_filename(file_name)
    if Path(safe).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise IngestError(f"unsupported file type; allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    if len(data) > max_bytes:
        raise IngestError(f"file is larger than the {max_bytes // (1024 * 1024)} MB limit")
    if source_hint and source_hint not in ADAPTERS_BY_NAME:
        raise IngestError(f"unknown source type {source_hint!r}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("file is not valid UTF-8 text") from exc

    records = _records(safe, text, max_records)
    result = FileResult(file_name=safe, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data), adapter=None, adapter_label=None)
    result.records_read = len(records)
    if not records:
        result.add_issue(None, "warning", "file contains no records")
        result.warnings += 1
        return result

    first = next((r for r in records if isinstance(r, dict)), None)
    adapter: SourceAdapter | None = detect_adapter(set(first.keys()) if first else set(), source_hint)
    if adapter is None:
        raise IngestError("could not recognise the log schema; choose a source type explicitly or use the common schema")
    result.adapter, result.adapter_label = adapter.name, adapter.label
    _process_records(records, adapter, result, row_of=lambda idx: idx + 1 if safe.lower().endswith(".csv") else idx)
    return result


def _process_records(records: list[Any], adapter: SourceAdapter, result: FileResult, row_of) -> None:
    seen_ids: dict[str, str] = {}
    label = result.file_name
    for idx, rec in enumerate(records, start=1):
        row = row_of(idx)
        if isinstance(rec, _Unparseable):
            result.rejected += 1
            result.add_issue(rec.line, "error", "line is not valid JSON")
            continue
        if not isinstance(rec, dict):
            result.rejected += 1
            result.add_issue(row, "error", "record is not an object")
            continue
        try:
            if adapter.is_context:
                result.inventory.append(_inventory_item(rec, label, row))
                result.accepted += 1
                continue
            fields, notes = map_record(adapter, rec)
        except NormalizationError as exc:
            result.rejected += 1
            result.add_issue(row, "error", str(exc))
            continue

        digest = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
        eid = fields["event_id"]
        if eid in seen_ids:
            if seen_ids[eid] == digest:
                result.duplicates += 1
                result.add_issue(row, "duplicate", f"exact duplicate of event {eid}; ignored")
            else:
                result.conflicts += 1
                result.add_issue(row, "conflict", f"event id {eid} reused with different content; first occurrence kept")
            continue
        seen_ids[eid] = digest
        for n in notes:
            result.warnings += 1
            result.add_issue(row, "warning", n)
        ev = NormalizedEvent(
            uid=f"{fields['source_system']}:{eid}", source_file=label, source_row=row, notes=notes,
            raw={k: v for k, v in rec.items()}, **fields,
        )
        result.events.append(ev)
        result.accepted += 1
        if result.first_event is None or ev.timestamp < result.first_event:
            result.first_event = ev.timestamp
        if result.last_event is None or ev.timestamp > result.last_event:
            result.last_event = ev.timestamp


def ingest_records(records: list[Any], *, source_hint: str | None, max_records: int, row_offset: int = 0) -> FileResult:
    if len(records) > max_records:
        raise IngestError(f"batch exceeds the {max_records} record limit")
    if source_hint and source_hint not in ADAPTERS_BY_NAME:
        raise IngestError(f"unknown source type {source_hint!r}")
    first = next((r for r in records if isinstance(r, dict)), None)
    adapter = detect_adapter(set(first.keys()) if first else set(), source_hint)
    if adapter is None:
        raise IngestError("could not recognise the record schema; set source_type or use the common schema")
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, default=str).encode()).hexdigest()
    result = FileResult(file_name=f"live:{adapter.name}", sha256=digest, size_bytes=0, adapter=adapter.name,
                        adapter_label=adapter.label)
    result.records_read = len(records)
    _process_records(records, adapter, result, row_of=lambda idx: row_offset + idx)
    return result


def ingest_path(path: Path, *, max_bytes: int, max_records: int, source_hint: str | None = None) -> FileResult:
    if path.stat().st_size > max_bytes:
        raise IngestError(f"{path.name} is larger than the {max_bytes // (1024 * 1024)} MB limit")
    return ingest_bytes(path.read_bytes(), path.name, max_bytes=max_bytes, max_records=max_records, source_hint=source_hint)
