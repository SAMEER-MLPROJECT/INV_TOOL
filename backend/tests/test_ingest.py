import json

import pytest

from attackgraph.ingest.loader import IngestError, ingest_bytes, sanitize_filename

LIMITS = dict(max_bytes=1024 * 1024, max_records=1000)

AUTH_CSV = b"""event_id,time,user,src_host,dst_host,logon_type,result
A1,2026-01-01T10:00:00Z,CORP\\alice,WS-1,WS-1,interactive,success
A2,2026-01-01T10:01:00Z,alice,WS-1,SRV-1,network,success
A2,2026-01-01T10:01:00Z,alice,WS-1,SRV-1,network,success
A3,2026-01-01T10:02:00Z,alice,WS-1,SRV-1,network,failure
A3,2026-01-01T10:02:00Z,bob,WS-1,SRV-1,network,failure
A4,bad-time,alice,WS-1,SRV-1,network,success
A5,2026-01-01T10:03:00Z,,WS-1,SRV-1,network,success
A6,2026-01-01T10:04:00Z,alice,WS-1,SRV-1,network,perhaps
"""


def test_csv_ingestion_validation_duplicates_and_conflicts():
    r = ingest_bytes(AUTH_CSV, "auth.csv", **LIMITS)
    assert r.adapter == "idp_auth"
    assert r.records_read == 8
    assert r.accepted == 3  # A1, A2, A3
    assert r.duplicates == 1  # exact A2 copy
    assert r.conflicts == 1  # A3 reused with different content
    assert r.rejected == 3  # bad time, missing user, invalid result
    msgs = " | ".join(i.message for i in r.issues)
    assert "unparseable timestamp" in msgs and "missing required field" in msgs and "unknown authentication result" in msgs
    # provenance: CSV row numbers count the header line
    a2 = next(e for e in r.events if e.event_id == "A2")
    assert a2.source_file == "auth.csv" and a2.source_row == 3 and a2.uid == "idp_auth:A2"
    assert a2.raw["dst_host"] == "SRV-1"  # original record preserved verbatim
    assert r.events[0].user == "alice"  # CORP\alice normalized


def test_json_array_object_and_jsonl_formats():
    recs = [{"qid": "D1", "time": "2026-01-01T10:00:00+05:30", "client_ip": "10.0.0.5", "query": "Example.COM.", "answers": ["198.51.100.7"]}]
    a = ingest_bytes(json.dumps(recs).encode(), "dns.json", **LIMITS)
    b = ingest_bytes(json.dumps({"records": recs}).encode(), "dns2.json", **LIMITS)
    c = ingest_bytes((json.dumps(recs[0]) + "\n{broken\n").encode(), "dns.jsonl", **LIMITS)
    for r in (a, b):
        assert r.adapter == "dns" and r.accepted == 1
        ev = r.events[0]
        assert ev.domain == "example.com" and ev.dst_ip == "198.51.100.7"
        assert ev.timestamp.isoformat() == "2026-01-01T04:30:00+00:00"
        assert any("converted to UTC" in n for n in ev.notes)
    assert c.accepted == 1 and c.rejected == 1


def test_file_level_rejections():
    with pytest.raises(IngestError, match="unsupported file type"):
        ingest_bytes(b"x", "payload.exe", **LIMITS)
    with pytest.raises(IngestError, match="larger than"):
        ingest_bytes(b"a" * 2048, "big.csv", max_bytes=1024, max_records=10)
    with pytest.raises(IngestError, match="UTF-8"):
        ingest_bytes(b"\xff\xfe\x00bad", "x.csv", **LIMITS)
    with pytest.raises(IngestError, match="recognise"):
        ingest_bytes(b"foo,bar\n1,2\n", "x.csv", **LIMITS)
    with pytest.raises(IngestError, match="invalid JSON"):
        ingest_bytes(b"{nope", "x.json", **LIMITS)
    with pytest.raises(IngestError, match="record limit"):
        ingest_bytes(AUTH_CSV, "auth.csv", max_bytes=10**6, max_records=2)
    with pytest.raises(IngestError, match="unknown source type"):
        ingest_bytes(AUTH_CSV, "auth.csv", source_hint="nope", **LIMITS)


def test_empty_file_is_a_warning_not_a_crash():
    r = ingest_bytes(b"[]", "empty.json", **LIMITS)
    assert r.accepted == 0 and r.warnings == 1


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd.csv", "passwd.csv"),
    ("..\\..\\windows\\evil.csv", "evil.csv"),
    ("normal file (1).csv", "normal_file__1_.csv"),
    (".hidden.json", "hidden.json"),
])
def test_filename_sanitization_prevents_traversal(name, expected):
    assert sanitize_filename(name) == expected


def test_record_without_id_gets_deterministic_hash():
    data = b"time,user,src_host,dst_host,logon_type,result\n2026-01-01T10:00:00Z,a,W,W,interactive,success\n"
    r1 = ingest_bytes(data, "a.csv", **LIMITS)
    r2 = ingest_bytes(data, "b.csv", **LIMITS)
    assert r1.events[0].event_id == r2.events[0].event_id and r1.events[0].event_id.startswith("h-")


def test_source_hint_overrides_detection_and_alert_mapping():
    alerts = {"alerts": [{"alert_id": "X1", "created": "2026-01-01T10:00:00Z", "rule_name": "Test", "severity": "critical",
                          "entities": {"users": ["CORP\\Bob"], "hosts": ["srv-9.corp.local"], "ips": ["10.0.0.9", "junk"]},
                          "evidence_refs": ["E1"]}]}
    r = ingest_bytes(json.dumps(alerts).encode(), "a.json", source_hint="siem_alerts", **LIMITS)
    ev = r.events[0]
    assert ev.severity == 0.95 and ev.related_event_ids == ["E1"]
    assert ev.alert_entities == ["host:SRV-9", "ip:10.0.0.9", "user:bob"]


def test_inventory_validation():
    inv = b"asset_id,asset_type,name,ip,criticality\nA,server,SRV-1,10.0.0.1,4\nB,server,SRV-2,10.0.0.2,9\nC,toaster,T,,1\n"
    r = ingest_bytes(inv, "inv.csv", **LIMITS)
    assert r.adapter == "asset_inventory" and r.accepted == 1 and r.rejected == 2
    assert r.inventory[0].name == "SRV-1" and r.inventory[0].criticality == 4
