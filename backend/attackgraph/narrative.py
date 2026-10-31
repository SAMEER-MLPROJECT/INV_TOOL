"""Analyst-readable one-line descriptions of normalized events."""
from __future__ import annotations

from .models import NormalizedEvent


def describe_event(ev: NormalizedEvent) -> str:
    c = ev.category
    if c == "authentication":
        src = f" from {ev.src_host}" if ev.src_host else ""
        verb = "logged on to" if ev.outcome == "success" else "FAILED to log on to"
        return f"{ev.user or 'unknown user'} {verb} {ev.dst_host}{src} ({ev.action.removeprefix('logon:')})"
    if c == "process":
        parent = f" (parent {ev.parent_process})" if ev.parent_process else ""
        who = f" as {ev.user}" if ev.user else ""
        return f"{ev.process} started on {ev.src_host}{who}{parent}"
    if c == "network" and ev.source_system == "edr":
        port = f":{ev.dst_port}" if ev.dst_port else ""
        return f"{ev.process} on {ev.src_host} connected to {ev.dst_ip}{port}"
    if c == "network":
        port = f":{ev.dst_port}" if ev.dst_port else ""
        return f"Firewall {ev.outcome} {ev.src_ip} -> {ev.dst_ip}{port} ({ev.action.removeprefix('flow:')})"
    if c == "dns":
        ans = f" -> {ev.dst_ip}" if ev.dst_ip else ""
        return f"{ev.src_ip} resolved {ev.domain}{ans} [{ev.outcome}]"
    if c == "db_access":
        rows = ev.raw.get("rows_returned")
        rows_s = f", {rows} rows" if rows not in (None, "") else ""
        return f"{ev.src_host} ran {ev.action} on {ev.database} as {ev.user or 'unknown'}{rows_s}"
    if c == "privilege":
        return f"{ev.process} on {ev.src_host} obtained credential material for {ev.target_user}"
    if c == "service":
        return f"{ev.process} on {ev.src_host} installed service '{ev.service}'"
    if c == "alert":
        tech = f" [{ev.technique}]" if ev.technique else ""
        return f"ALERT {ev.alert_name}{tech} (severity {ev.severity:.2f}, {ev.disposition})"
    return f"{c} event {ev.event_id}"
