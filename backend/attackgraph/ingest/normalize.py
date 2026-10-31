from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

_HOST_DOMAIN_SUFFIX = re.compile(r"\.(corp|local|internal|lan|ad)(\..*)?$", re.IGNORECASE)
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9._\-$@]")

SEVERITY_WORDS = {
    "info": 0.05,
    "informational": 0.05,
    "low": 0.25,
    "medium": 0.5,
    "moderate": 0.5,
    "high": 0.75,
    "critical": 0.95,
}

MIN_YEAR, MAX_YEAR = 2000, 2100


class NormalizationError(ValueError):
    pass


def parse_timestamp(value: object) -> tuple[datetime, str | None]:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise NormalizationError("missing timestamp")
    note: str | None = None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value.strip())):
        num = float(value)
        if num > 1e12:
            num /= 1000.0
        dt = datetime.fromtimestamp(num, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        if " " in text and "T" not in text:
            text = text.replace(" ", "T", 1)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise NormalizationError(f"unparseable timestamp {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            note = "timestamp had no timezone; interpreted as UTC"
        elif dt.utcoffset() and dt.utcoffset().total_seconds() != 0:
            note = f"timestamp converted to UTC from offset {dt.strftime('%z')}"
        dt = dt.astimezone(timezone.utc)
    else:
        raise NormalizationError(f"unsupported timestamp type {type(value).__name__}")
    if not (MIN_YEAR <= dt.year <= MAX_YEAR):
        raise NormalizationError(f"timestamp out of accepted range: {dt.isoformat()}")
    return dt, note


def clean(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"-", "null", "none", "n/a", "na", "unknown"}:
        return None
    return text


def norm_user(value: object) -> str | None:
    text = clean(value)
    if text is None:
        return None
    if "\\" in text:
        text = text.split("\\")[-1]
    if "@" in text:
        text = text.split("@")[0]
    text = _SAFE_TOKEN.sub("", text).lower()
    return text or None


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10")]


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in _INTERNAL_NETS)


def norm_ip(value: object) -> str | None:
    text = clean(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def norm_host(value: object) -> str | None:
    text = clean(value)
    if text is None:
        return None
    if is_ip(text):
        return text
    text = _HOST_DOMAIN_SUFFIX.sub("", text)
    text = _SAFE_TOKEN.sub("", text).upper()
    return text or None


def norm_process(value: object) -> str | None:
    text = clean(value)
    if text is None:
        return None
    text = text.replace("\\", "/").split("/")[-1]
    text = _SAFE_TOKEN.sub("", text).lower()
    return text or None


def norm_severity(value: object) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, str):
        key = value.strip().lower()
        if key in SEVERITY_WORDS:
            return SEVERITY_WORDS[key]
        try:
            value = float(key)
        except ValueError:
            return 0.0
    num = float(value)  # type: ignore[arg-type]
    if num <= 1.0:
        return max(0.0, num)
    if num <= 10.0:
        return num / 10.0
    return min(num, 100.0) / 100.0


def to_int(value: object) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None
