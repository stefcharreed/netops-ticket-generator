"""logs.xlsx: one row per event, the way a syslog collector export looks."""
from __future__ import annotations

import random
from pathlib import Path

from openpyxl import Workbook

from packetgen.registry import render_message
from packetgen.timebase import header, parse_utc

COLUMNS = ["log_id", "received_utc", "host", "message"]


def ordered_events(spec: dict) -> list[dict]:
    """Collector arrival order: by time, then `shuffle_rows` seeded adjacent swaps (UDP reordering)."""
    events = sorted(spec["events"], key=lambda e: (parse_utc(e["t"]), e["id"]))
    rng = random.Random(spec["meta"]["id"])
    for _ in range(spec["meta"]["difficulty"].get("shuffle_rows", 0)):
        if len(events) > 1:
            i = rng.randrange(len(events) - 1)
            events[i], events[i + 1] = events[i + 1], events[i]
    return events


def render_logs(spec: dict, registry: dict[str, dict], out: Path) -> dict[str, int]:
    out.mkdir(parents=True, exist_ok=True)
    devices = {d["hostname"]: d for d in spec["topology"]["devices"]}
    wb = Workbook()
    ws = wb.active
    assert ws is not None  # a new Workbook always has one sheet
    ws.title = "logs"
    ws.append(COLUMNS)
    manifest = {}
    for n, ev in enumerate(ordered_events(spec), start=1):
        device = devices[ev["device"]]
        utc = parse_utc(ev["t"])
        line = header(device["header_style"], utc, device) + render_message(registry[ev["format_id"]], ev["fields"])
        # openpyxl can't store tz-aware datetimes; the column is UTC by name.
        ws.append([n, utc.replace(tzinfo=None), ev["device"], line])
        ws.cell(row=n + 1, column=2).number_format = "yyyy-mm-dd hh:mm:ss"
        manifest[ev["id"]] = n + 1
    ws.column_dimensions["B"].width = 20
    ws.column_dimensions["D"].width = 120
    wb.save(out / "logs.xlsx")
    return manifest
