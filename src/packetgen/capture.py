"""Capture block helpers: endpoint resolution and output filename.

Seam discipline: returns plain data, never prints. (Truth checks arrive later.)
"""
from __future__ import annotations

import re

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def resolve_endpoint(spec: dict, name: str) -> dict | None:
    """Resolve an endpoint name to {"mac", "ip"} (either may be None), or None.

    Order: topology entity `name`; `HOST:IFNAME` device interface; `HOST` when the
    device has exactly one interface.
    """
    topo = spec.get("topology", {})
    ent = topo.get("entities", {}).get(name)
    if ent is not None:
        return {"mac": ent.get("mac"), "ip": ent.get("ip")}
    host, sep, ifname = name.partition(":")
    for dev in topo.get("devices", []):
        if dev.get("hostname") != host:
            continue
        ifaces = dev.get("interfaces", [])
        if sep:
            match = [i for i in ifaces if i.get("name") == ifname]
        else:
            match = ifaces if len(ifaces) == 1 else []
        if match:
            return {"mac": match[0].get("mac"), "ip": match[0].get("ip")}
    return None


def capture_filename(spec: dict) -> str:
    """e.g. capture_ACC-SW1_Gi1-0-48.pcap ('/' and ':' in the interface become '-')."""
    cap = spec["capture"]
    return f"capture_{_UNSAFE.sub('-', cap['device'])}_{_UNSAFE.sub('-', cap['interface'])}.pcap"
