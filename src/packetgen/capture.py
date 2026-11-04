"""Capture block helpers: endpoint resolution and output filename.

Seam discipline: returns plain data, never prints. (Truth checks arrive later.)
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta

from jsonschema import Draft202012Validator

from packetgen.capture_kinds import KINDS, span_s
from packetgen.findings import finding
from packetgen.timebase import parse_utc

_DEAD, _ALIVE = "IOS:RADIUS-4-RADIUS_DEAD", "IOS:RADIUS-4-RADIUS_ALIVE"
_DEAD_LEAD = timedelta(seconds=30)  # a switch marks a server dead ~30 s after the first unanswered request
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_MAC = re.compile(r"[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}")


def parse_mac(text: str) -> bytes | None:
    """Colon, dash or Cisco-dotted MAC text -> 6 bytes, or None when it isn't one."""
    if not isinstance(text, str) or not _MAC.fullmatch(text):
        return None
    return bytes.fromhex(re.sub(r"[:.\-]", "", text))


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


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


# --- validation (PK1-PK5) -----------------------------------------------------------------

def check_capture(spec: dict) -> list[dict]:
    """PK1-PK5 for the optional `capture` block. [] when absent. Assumes T1 passed (times parse)."""
    cap = spec.get("capture")
    if not cap:
        return []
    out = _check_pk1(spec, cap) + _check_pk2_window(spec, cap) + _check_pk3_addresses(spec)
    for fl in cap["flows"]:
        kind = KINDS.get(fl["kind"])
        if kind is None:
            continue
        pk4 = _check_pk4(fl, kind)
        out += pk4 + _check_pk3(spec, fl, kind) + _check_pk5_symptom(fl, kind)
        if pk4:
            continue  # params aren't schema-valid: span_s and timing checks would be guesses
        out += _check_pk2_flow(cap, fl) + _check_pk5_radius(spec, fl)
    return out


def capture_strings(spec: dict) -> list[tuple[str, str]]:
    """(where, text) for every string param value of every flow, for the L1 answer-leak check."""
    cap = spec.get("capture") or {}
    return [(f"{fl['id']} params.{k}", v)
            for fl in cap.get("flows", []) for k, v in fl["params"].items() if isinstance(v, str)]


def capture_text(spec: dict) -> str:
    """Every mac/ip of every topology entity and interface (noise included), plus every flow string param, one per line (for the sanitize gate)."""
    cap = spec["capture"]
    topo = spec["topology"]
    # Whole topology, not just the capture pair: implicit ARP noise draws on any entity or interface.
    hosts = list(topo.get("entities", {}).values()) + [i for d in topo["devices"] for i in d.get("interfaces", [])]
    lines = [f"{h.get('mac') or ''} {h.get('ip') or ''}" for h in hosts]
    for fl in cap["flows"]:
        names = [fl.get(r) for r in ("src", "dst", "via")]
        names += [fl["params"].get(k) for k in ("client", "answer")]
        for name in names:
            ep = resolve_endpoint(spec, name) if isinstance(name, str) else None
            if ep:
                lines.append(f"{ep['mac'] or ''} {ep['ip'] or ''}")
        lines += [v for v in fl["params"].values() if isinstance(v, str)]
    return "\n".join(lines)


def _check_pk1(spec: dict, cap: dict) -> list[dict]:
    out = []
    ifaces = {d["hostname"]: {i["name"] for i in d.get("interfaces", [])} for d in spec["topology"]["devices"]}
    for role, dev, ifname in (("device", cap["device"], cap["interface"]),
                              ("peer", cap["peer"], cap["peer_interface"])):
        if dev not in ifaces:
            out.append(finding("PK1", f"capture.{role} {dev} is not in topology", "use a topology device hostname"))
        elif ifname not in ifaces[dev]:
            out.append(finding("PK1", f"capture: {dev} has no interface {ifname}",
                               f"declare it under {dev}'s interfaces[]"))
    pairs = [frozenset(link) for link in spec["topology"]["links"]]
    if frozenset((cap["device"], cap["peer"])) not in pairs:
        out.append(finding("PK1", f"capture: {cap['device']} and {cap['peer']} are not linked",
                           "add the pair to topology.links"))
    return out


def _check_pk2_window(spec: dict, cap: dict) -> list[dict]:
    start, end = parse_utc(cap["start"]), parse_utc(cap["end"])
    w = spec["meta"]["window"]
    out = []
    if start >= end:
        out.append(finding("PK2", "capture.start is not before capture.end", "start must precede end"))
    if start < parse_utc(w["start"]) or end > parse_utc(w["end"]):
        out.append(finding("PK2", "capture start/end is outside meta.window", "keep the capture inside the window"))
    return out


def _check_pk2_flow(cap: dict, fl: dict) -> list[dict]:
    start, end = parse_utc(cap["start"]), parse_utc(cap["end"])
    t = parse_utc(fl["t"])
    if t < start or t + timedelta(seconds=span_s(fl)) > end:
        return [finding("PK2", f"{fl['id']}: t={fl['t']} plus its {span_s(fl):g} s span doesn't fit the capture",
                        "move the flow inside capture.start..end (end inclusive)")]
    return []


def _check_pk3(spec: dict, fl: dict, kind: dict) -> list[dict]:
    fid, out, ends = fl["id"], [], {}
    for role in ("src", "dst", "via"):
        name = fl.get(role)
        if name is None:
            continue  # only via may be null
        ends[role] = resolve_endpoint(spec, name)
        if ends[role] is None:
            out.append(finding("PK3", f"{fid}: {role} {name!r} doesn't resolve", "use an entity name or HOST:IFNAME"))
    for role in ("src", "dst"):
        if ends.get(role) is not None:
            out += [finding("PK3", f"{fid}: {role} {fl[role]!r} has no {attr}", f"declare its {attr} in topology")
                    for attr in kind["needs"][role] if not ends[role][attr]]
    if fl["kind"] != "arp":  # arp requests go to broadcast; everything else is unicast toward via/dst
        hop = "via" if fl.get("via") is not None else "dst"
        if ends.get(hop) is not None and not ends[hop]["mac"]:
            out.append(finding("PK3", f"{fid}: {hop} {fl[hop]!r} has no mac (frames toward dst need one)",
                               "declare its mac in topology"))
    params = fl["params"]
    if fl["kind"] == "radius_request" and isinstance(params.get("client"), str):
        client = spec["topology"]["entities"].get(params["client"])
        if client is None or not client.get("mac"):
            out.append(finding("PK3", f"{fid}: client {params['client']!r} is not an entity with a mac",
                               "declare it under topology.entities with a mac"))
    if fl["kind"] == "dns_query" and isinstance(params.get("answer"), str):
        answer = resolve_endpoint(spec, params["answer"])
        if not answer or not answer["ip"]:
            out.append(finding("PK3", f"{fid}: answer {params['answer']!r} doesn't resolve to an ip",
                               "declare it under topology.entities with an ip"))
    return out


def _check_pk3_addresses(spec: dict) -> list[dict]:
    """Every mac/ip the renderer can touch (flow endpoints, clients, answers and noise hosts) must parse.

    Checks the whole topology: noise draws on any entity or interface, and a bad one would crash build.
    """
    topo = spec["topology"]
    hosts = list(topo.get("entities", {}).items())
    hosts += [(f"{d['hostname']}:{i['name']}", i) for d in topo["devices"] for i in d.get("interfaces", [])]
    out = []
    for name, h in hosts:
        if h.get("mac") and parse_mac(h["mac"]) is None:
            out.append(finding("PK3", f"{name}: mac {h['mac']!r} is not a MAC address",
                               "use colon, dash or Cisco-dotted hex, e.g. 00:00:5e:00:53:01"))
        if h.get("ip") and not _is_ipv4(h["ip"]):
            out.append(finding("PK3", f"{name}: ip {h['ip']!r} is not an IPv4 address",
                               "the capture renderer supports IPv4 only"))
    return out


def _check_pk4(fl: dict, kind: dict) -> list[dict]:
    fid, params = fl["id"], fl["params"]
    errs = sorted(Draft202012Validator(kind["params"]).iter_errors(params), key=lambda e: list(map(str, e.path)))
    out = [finding("PK4", f"{fid}: {e.message}", f"fix params for {fl['kind']}") for e in errs]
    if out:
        return out
    if fl["kind"] == "arp" and params["outcome"] == "gratuitous" and fl["dst"] != fl["src"]:
        out.append(finding("PK4", f"{fid}: gratuitous ARP must have dst == src", "set dst to the same endpoint as src"))
    if fl["kind"] == "dns_query" and params["outcome"] == "ok":
        if "answer" not in params:
            out.append(finding("PK4", f"{fid}: outcome ok needs an answer", "add params.answer"))
        if params.get("qtype") == "AAAA":
            out.append(finding("PK4", f"{fid}: AAAA answers aren't supported yet", "use qtype A, or a non-ok outcome"))
    return out


def _check_pk5_symptom(fl: dict, kind: dict) -> list[dict]:
    if fl["label"] == "symptom" and not kind["symptom_rule"]:
        return [finding("PK5", f"{fl['id']}: {fl['kind']} has no symptom rule, so it can't be labelled symptom",
                        "label it noise/unrelated, or use a kind with a symptom rule")]
    return []


def _check_pk5_radius(spec: dict, fl: dict) -> list[dict]:
    if fl["kind"] != "radius_request":
        return []
    dst = resolve_endpoint(spec, fl["dst"])
    if not dst or not dst["ip"]:
        return []  # PK3 already reported it
    host, t, outcome = fl["src"].partition(":")[0], parse_utc(fl["t"]), fl["params"]["outcome"]
    events = [e for e in spec["events"] if e["device"] == host and e["fields"].get("ip") == dst["ip"]]
    dead = sorted(parse_utc(e["t"]) for e in events if e["format_id"] == _DEAD)
    alive = sorted(parse_utc(e["t"]) for e in events if e["format_id"] == _ALIVE)
    periods = [(d, next((a for a in alive if a > d), None)) for d in dead]  # None = still dead at the end

    def inside(lead: timedelta) -> bool:
        return any(d - lead <= t and (a is None or t < a) for d, a in periods)

    if outcome == "no_response" and not inside(_DEAD_LEAD):
        return [finding("PK5", f"{fl['id']}: unanswered request at {fl['t']} isn't in a dead period for "
                               f"{host} -> {dst['ip']}",
                        f"emit an {_DEAD} event on {host} for {dst['ip']} within 30 s after it")]
    if outcome != "no_response" and inside(timedelta(0)):
        return [finding("PK5", f"{fl['id']}: {outcome} at {fl['t']} while {host} has {dst['ip']} marked dead",
                        "answer from a live server, or move the flow outside the dead period")]
    return []
