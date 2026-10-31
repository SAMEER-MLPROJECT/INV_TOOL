from datetime import datetime, timezone

import pytest

from attackgraph.ingest.normalize import (
    NormalizationError,
    is_private_ip,
    norm_host,
    norm_process,
    norm_severity,
    norm_user,
    parse_timestamp,
)

UTC = timezone.utc


@pytest.mark.parametrize("value,expected,note", [
    ("2026-10-27T20:40:00Z", datetime(2026, 10, 27, 20, 40, tzinfo=UTC), None),
    ("2026-10-28T02:10:00+05:30", datetime(2026, 10, 27, 20, 40, tzinfo=UTC), "offset"),
    ("2026-10-27 20:40:00", datetime(2026, 10, 27, 20, 40, tzinfo=UTC), "no timezone"),
    (1793133600, datetime(2026, 10, 27, 20, 40, tzinfo=UTC), None),
    ("1793133600000", datetime(2026, 10, 27, 20, 40, tzinfo=UTC), None),
])
def test_timestamps_normalized_to_utc(value, expected, note):
    dt, n = parse_timestamp(value)
    assert dt == expected and dt.tzinfo is not None
    if note:
        assert note in n
    else:
        assert n is None


@pytest.mark.parametrize("bad", [None, "", "not-a-time", "1899-01-01T00:00:00Z", "2026-13-01T00:00:00Z", [1, 2]])
def test_invalid_timestamps_rejected(bad):
    with pytest.raises(NormalizationError):
        parse_timestamp(bad)


def test_identifier_normalization():
    assert norm_user("CORP\\Sameer") == norm_user("sameer@corp.local") == norm_user(" SAMEER ") == "sameer"
    assert norm_user("-") is None and norm_user("") is None
    assert norm_host("ws-014.corp.local") == norm_host("WS-014") == "WS-014"
    assert norm_host("10.1.2.3") == "10.1.2.3"
    assert norm_process("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE") == "powershell.exe"


def test_severity_scales():
    assert norm_severity("high") == 0.75
    assert norm_severity(7) == 0.7
    assert norm_severity(85) == 0.85
    assert norm_severity(0.3) == 0.3
    assert norm_severity("nonsense") == 0.0


def test_internal_vs_external_addresses():
    assert is_private_ip("10.10.1.14") and is_private_ip("192.168.0.1") and is_private_ip("172.20.0.1")
    assert not is_private_ip("203.0.113.45") and not is_private_ip("198.51.100.20")
    assert not is_private_ip("not-an-ip")
