"""One UTC clock per scenario, rendered per device.

Header formats per style are in `header()` below and summarized in docs/DESIGN.md.
Every device header derives from the same UTC instant plus that device's tz offset and clock skew,
which is what keeps a packet's files consistent with each other.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

STYLES = ("ios", "nxos", "asa", "bsd", "meraki")


def parse_utc(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"naive timestamp (no Z or offset): {s!r}")
    return dt.astimezone(timezone.utc)


def device_time(utc: datetime, device: dict) -> datetime:
    """The instant as the device's clock shows it: skewed if unsynced, in its fixed offset."""
    skew = device.get("skew_s", 0) if device.get("clock") == "unsynced" else 0
    tz = timezone(timedelta(minutes=device.get("tz_offset_min", 0)))
    return (utc + timedelta(seconds=skew)).astimezone(tz)


def _zone_label(dt: datetime) -> str:
    offset = dt.utcoffset() or timedelta(0)
    if not offset:
        return "UTC"
    minutes = int(offset.total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def _mon_day(dt: datetime) -> str:
    return f"{dt:%b} {dt.day:>2}"  # syslog pads the day with a space; %e isn't portable


def header(style: str, utc: datetime, device: dict, seq: int | None = None) -> str:
    dt = device_time(utc, device)
    host = device.get("hostname", "")
    if style == "ios":
        prefix = f"{seq}: " if seq is not None else ""
        return f"{prefix}{_mon_day(dt)} {dt:%H:%M:%S}.{dt.microsecond // 1000:03d} {_zone_label(dt)}: "
    if style == "nxos":
        return f"{dt:%Y} {_mon_day(dt)} {dt:%H:%M:%S} {host} "
    if style == "asa":
        return f"{dt:%b %d %Y %H:%M:%S} {host} : "
    if style == "bsd":
        return f"{_mon_day(dt)} {dt:%H:%M:%S} {host} "
    if style == "meraki":
        ns = round(dt.timestamp() * 1_000_000) * 1000  # µs precision is plenty; avoids float ns drift
        return f"{ns // 1_000_000_000}.{ns % 1_000_000_000:09d} {host} "
    raise ValueError(f"unsupported header style {style!r}; expected one of {STYLES}")
