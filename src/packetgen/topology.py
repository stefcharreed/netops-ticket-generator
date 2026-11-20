"""Topology helpers: link ends, icon kinds, and the documented rows NETWORK.md shows.

Docs are drawn only from `topology` (and its `documented` overrides): never from events, telemetry or the answer.
"""
from __future__ import annotations

import re

# Icon kinds (schema enum for `icon` / `kind`; tests/test_schema_drift.py keeps them in step).
KINDS = ("cloud", "firewall", "router", "l3switch", "switch", "wlc", "ap", "server", "aaa", "pc", "printer",
         "phone", "host")

# First matching token wins, so "core-switch" is l3switch, not switch.
_DEVICE_TOKENS = (
    ("firewall", {"firewall", "fw", "asa", "ftd", "palo", "pa"}),
    ("wlc", {"wlc", "controller"}),
    ("ap", {"ap", "accesspoint"}),
    ("router", {"router", "rtr", "wan", "isr", "asr"}),
    ("l3switch", {"core", "distribution", "dist", "l3"}),
    ("switch", {"switch", "access", "sw"}),
    ("aaa", {"ise", "radius", "acs", "aaa"}),
    ("server", {"server", "dhcp", "dns", "ntp", "srv"}),
    ("cloud", {"cloud", "internet", "isp"}),
)
_ENTITY_TOKENS = (
    ("aaa", {"ise", "radius", "acs", "aaa"}),
    ("server", {"server", "srv", "dns", "dhcp", "ntp", "nas", "ad", "ldap", "web", "file", "syslog"}),
    ("printer", {"printer", "prn", "print"}),
    ("phone", {"phone", "voip"}),
    ("ap", {"ap"}),
    ("pc", {"pc", "laptop", "workstation", "client", "desktop"}),
    ("cloud", {"cloud", "internet", "isp"}),
)


def _tokens(text: str) -> set[str]:
    return set(re.split(r"[^a-z0-9]+", text.lower())) - {""}


def _match(text: str, table: tuple[tuple[str, set[str]], ...]) -> str:
    toks = _tokens(text)
    return next((kind for kind, words in table if toks & words), "host")


def device_kind(dev: dict) -> str:
    return dev.get("icon") or _match(dev.get("role", ""), _DEVICE_TOKENS)


def entity_kind(name: str, ent: dict) -> str:
    return ent.get("kind") or _match(name, _ENTITY_TOKENS)


def link_ends(spec: dict) -> list[tuple[str, str | None, str, str | None]]:
    """Each link as (host_a, if_a, host_b, if_b). Ends are `HOST` or `HOST:IFNAME`."""
    out = []
    for a, b in spec["topology"]["links"]:
        ha, _, ia = a.partition(":")
        hb, _, ib = b.partition(":")
        out.append((ha, ia or None, hb, ib or None))
    return out


_SHORT = (("TenGigabitEthernet", "Te"), ("TwentyFiveGigE", "Twe"), ("FortyGigabitEthernet", "Fo"),
          ("HundredGigE", "Hu"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("Port-channel", "Po"),
          ("Ethernet", "Eth"))


def short_if(name: str | None) -> str:
    """GigabitEthernet1/0/49 -> Gi1/0/49 (the way diagrams label ports)."""
    if not name:
        return ""
    return next((short + name[len(long):] for long, short in _SHORT if name.startswith(long)), name)


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9-]+", "-", text).strip("-")


def _pick(real, documented: dict, key: str):
    """(value shown in the docs, whether it's a documented override)."""
    if key in documented and documented[key] != real:
        return documented[key], True
    return real, False


def doc_rows(spec: dict) -> list[dict]:
    """Documented addressing rows: device mgmt, device interfaces with an ip or vlan, entities with an ip."""
    topo = spec["topology"]
    rows = []
    for d in topo["devices"]:
        host, doc = d["hostname"], d.get("documented", {})
        ip, overridden = _pick(d["mgmt_ip"], doc, "mgmt_ip")
        rows.append({"id": f"doc:{slug(host)}-mgmt", "device": host, "interface": "mgmt", "ip": ip, "vlan": None,
                     "documented": overridden})
        for i in d.get("interfaces", []):
            if "ip" not in i and "vlan" not in i:
                continue
            idoc = i.get("documented", {})
            ip, o1 = _pick(i.get("ip"), idoc, "ip")
            vlan, o2 = _pick(i.get("vlan"), idoc, "vlan")
            rows.append({"id": f"doc:{slug(host)}-{slug(i['name'])}", "device": host, "interface": i["name"],
                         "ip": ip, "vlan": vlan, "documented": o1 or o2})
    for name, e in sorted(topo["entities"].items()):
        if "ip" not in e:
            continue
        ip, overridden = _pick(e["ip"], e.get("documented", {}), "ip")
        att = e.get("attached", {})
        port = " ".join(p for p in (att.get("device"), short_if(att.get("interface"))) if p)
        rows.append({"id": f"doc:{slug(name)}", "device": name, "interface": port, "ip": ip,
                     "vlan": att.get("vlan"), "documented": overridden})
    return rows


def mac_rows(spec: dict) -> list[dict]:
    """Documented MAC table rows: entities that have both a mac and an attachment point."""
    rows = []
    for name, e in sorted(spec["topology"]["entities"].items()):
        att = e.get("attached")
        if not (att and "mac" in e):
            continue
        mac, overridden = _pick(e["mac"], e.get("documented", {}), "mac")
        rows.append({"id": f"doc:mac-{slug(name)}", "mac": mac, "ip": e.get("ip"), "switch": att["device"],
                     "port": att.get("interface"), "vlan": att.get("vlan"), "documented": overridden})
    return rows


def overrides(spec: dict) -> list[tuple[str, str, str, str]]:
    """Every documented value that differs from the gear: (row id, field, documented, real)."""
    topo, out = spec["topology"], []
    for d in topo["devices"]:
        doc = d.get("documented", {})
        if "mgmt_ip" in doc and doc["mgmt_ip"] != d["mgmt_ip"]:
            out.append((f"doc:{slug(d['hostname'])}-mgmt", "ip", doc["mgmt_ip"], d["mgmt_ip"]))
        for i in d.get("interfaces", []):
            for k, v in i.get("documented", {}).items():
                if v != i.get(k):
                    out.append((f"doc:{slug(d['hostname'])}-{slug(i['name'])}", k, v, i.get(k)))
    for name, e in sorted(topo["entities"].items()):
        for k, v in e.get("documented", {}).items():
            if v != e.get(k):
                rid = f"doc:mac-{slug(name)}" if k == "mac" else f"doc:{slug(name)}"
                out.append((rid, k, v, e.get(k)))
    return out
