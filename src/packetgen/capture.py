"""Capture block helpers: endpoint resolution and output filename.

Seam discipline: returns plain data, never prints. (Truth checks arrive later.)
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta

from jsonschema import Draft202012Validator

from packetgen.capture_kinds import KINDS, span_s
from packetgen.capture_views import flow_class, flow_vlan, keeps, method_label, sender_native
from packetgen.findings import finding
from packetgen.timebase import parse_utc
from packetgen.topology import link_ends, short_if

_DEAD, _ALIVE = "IOS:RADIUS-4-RADIUS_DEAD", "IOS:RADIUS-4-RADIUS_ALIVE"
_DEAD_LEAD = timedelta(seconds=30)  # a switch marks a server dead ~30 s after the first unanswered request
_MULTICAST_KINDS = {"arp", "stp_bpdu", "cdp", "hsrp_hello"}  # broadcast/multicast: no next-hop mac needed
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
    """Resolve an endpoint name to {"mac", "ip", "vlan"} (any may be None), or None.

    Order: topology entity `name`; `HOST:IFNAME` device interface; `HOST` when the
    device has exactly one interface.
    """
    topo = spec.get("topology", {})
    ent = topo.get("entities", {}).get(name)
    if ent is not None:
        return {"mac": ent.get("mac"), "ip": ent.get("ip"), "vlan": (ent.get("attached") or {}).get("vlan")}
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
            return {"mac": match[0].get("mac"), "ip": match[0].get("ip"), "vlan": match[0].get("vlan")}
    return None


def capture_filename(spec: dict) -> str:
    """e.g. capture_ACC-SW1_Gi1-0-48.pcap ('/' and ':' in the interface become '-')."""
    cap = spec["capture"]
    return f"capture_{_UNSAFE.sub('-', cap['device'])}_{_UNSAFE.sub('-', cap['interface'])}.pcap"


_ALLOWED = re.compile(r"^\s*switchport trunk allowed vlan\s+(.+?)\s*$", re.MULTILINE)
_NATIVE = re.compile(r"^\s*switchport trunk native vlan\s+(\d+)\s*$", re.MULTILINE)
_VLAN_LIST = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")


def parse_allowed_vlans(text: str) -> set[int] | None:
    """VLANs from the last `switchport trunk allowed vlan <list>` line, or None (no line, or add/remove/all/...)."""
    lines = _ALLOWED.findall(text)
    if not lines or not _VLAN_LIST.fullmatch(lines[-1].replace(" ", "")):
        return None
    out: set[int] = set()
    for part in lines[-1].replace(" ", "").split(","):
        lo, _, hi = part.partition("-")
        out |= set(range(int(lo), int(hi or lo) + 1))
    return out


def _stanza(text: str, ifname: str) -> str | None:
    """The `interface <ifname>` stanza of a config snippet (long or short names match), or None."""
    out: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("interface "):
            if out is not None:
                break
            if short_if(line.split(None, 1)[1].strip()) == short_if(ifname):
                out = []
        elif out is not None and line[:1] not in (" ", "\t", ""):
            break
        elif out is not None:
            out.append(line)
    return None if out is None else "\n".join(out)


def stanza_decision(spec: dict, t: datetime, device: str, ifname: str, line_re: re.Pattern) -> str | None:
    """The `after` stanza ('' when after lacks it) of the newest diff on device at or before t whose
    `interface <ifname>` stanza has a line_re line in before or after; None when no diff decides."""
    diffs = sorted((parse_utc(c["t_change"]), i, c) for i, c in enumerate(spec.get("config_diffs", []))
                   if c["device"] == device and parse_utc(c["t_change"]) <= t)
    for _, _, c in reversed(diffs):
        before, after = _stanza(c["before"], ifname), _stanza(c["after"], ifname)
        if any(x is not None and line_re.search(x) for x in (before, after)):
            return after or ""
    return None


def _peer_decision(spec: dict, t: datetime, line_re: re.Pattern) -> str | None:
    cap = spec["capture"]
    if not cap.get("peer_interface"):
        return None
    return stanza_decision(spec, t, cap["peer"], cap["peer_interface"], line_re)


def peer_allowed_vlans(spec: dict, t: datetime) -> set[int] | None:
    """The allowed list on the monitored trunk's far end (capture.peer peer_interface) in force at t, or None (all).

    The newest diff at or before t whose stanza for that interface has an allowed-vlan line in before or after
    decides: its after list, or None when after has no line (all VLANs) or a form this can't read (add/remove).
    """
    after = _peer_decision(spec, t, _ALLOWED)
    return None if after is None else parse_allowed_vlans(after)


def peer_native_vlan(spec: dict, t: datetime) -> int | None:
    """The far end's trunk native VLAN in force at t (1 when the deciding diff drops the line), or None."""
    after = _peer_decision(spec, t, _NATIVE)
    if after is None:
        return None
    found = _NATIVE.findall(after)
    return int(found[-1]) if found else 1


def port_down_at(spec: dict) -> datetime | None:
    """When the monitored port went err-disabled (earliest IOS:PM-4-ERR_DISABLE for it on capture.device), or None."""
    cap = spec["capture"]
    times = [parse_utc(e["t"]) for e in spec.get("events", [])
             if e["format_id"] == "IOS:PM-4-ERR_DISABLE" and e["device"] == cap["device"]
             and short_if(e["fields"].get("interface")) == short_if(cap["interface"])]
    return min(times, default=None)


# --- validation (PK1-PK5) -----------------------------------------------------------------

def check_capture(spec: dict) -> list[dict]:
    """PK1-PK5 for the optional `capture` block. [] when absent. Assumes T1 passed (times parse)."""
    cap = spec.get("capture")
    if not cap:
        return []
    out = _check_pk1(spec, cap) + _check_pk2_window(spec, cap) + _check_pk3_addresses(spec) + _check_pk9(spec, cap)
    for fl in cap["flows"]:
        kind = KINDS.get(fl["kind"])
        if kind is None:
            continue
        pk4 = _check_pk4(spec, fl, kind)
        out += pk4 + _check_pk3(spec, fl, kind) + _check_pk5_symptom(fl, kind)
        if pk4:
            continue  # params aren't schema-valid: span_s and timing checks would be guesses
        out += _check_pk2_flow(cap, fl) + _check_pk5_radius(spec, fl) + _check_pk5_arp(spec, fl) + _check_pk5_l2(spec, fl)
        out += _check_pk8(spec, fl) + _check_pk9_vlan(spec, fl)
    return out


def capture_strings(spec: dict) -> list[tuple[str, str]]:
    """(where, text) for every string param value of every flow, for the L1 answer-leak check."""
    cap = spec.get("capture") or {}
    reason = [("capture.reason", cap["reason"])] if isinstance(cap.get("reason"), str) else []
    return reason + [(f"{fl['id']} params.{k}", v)
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
    ent = spec["topology"].get("entities", {}).get(cap["peer"])
    if cap["peer"] not in ifaces and ent is not None:  # a PC or hub on the monitored port
        att = ent.get("attached") or {}
        if att.get("device") != cap["device"] or att.get("interface", cap["interface"]) != cap["interface"]:
            out.append(finding("PK1", f"capture: peer {cap['peer']} is not attached to {cap['device']} "
                                      f"{cap['interface']}", "set the entity's attached device/interface"))
        if cap["device"] not in ifaces:
            out.append(finding("PK1", f"capture.device {cap['device']} is not in topology",
                               "use a topology device hostname"))
        return out
    if "peer_interface" not in cap:
        return [finding("PK1", "capture: a device peer needs peer_interface", "add capture.peer_interface")]
    for role, dev, ifname in (("device", cap["device"], cap["interface"]),
                              ("peer", cap["peer"], cap["peer_interface"])):
        if dev not in ifaces:
            out.append(finding("PK1", f"capture.{role} {dev} is not in topology", "use a topology device hostname"))
        elif ifname not in ifaces[dev]:
            out.append(finding("PK1", f"capture: {dev} has no interface {ifname}",
                               f"declare it under {dev}'s interfaces[]"))
    pairs = [frozenset((a, b)) for a, _, b, _ in link_ends(spec)]  # ends may be HOST or HOST:IFNAME
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
    if fl["kind"] == "dhcp":  # broadcast out, relayed back: the relay (gateway) is the far side
        relay = ends.get("via")
        if fl.get("via") is None or (relay is not None and not (relay["mac"] and relay["ip"])):
            out.append(finding("PK3", f"{fid}: dhcp needs via, the relay with a mac and ip",
                               "set via to the client VLAN's gateway (ip helper), e.g. HOST:Vlan20"))
        if fl["params"].get("outcome") == "ack" and ends.get("src") is not None and not ends["src"]["ip"]:
            out.append(finding("PK3", f"{fid}: an ack leases the src's ip, but {fl['src']!r} has none",
                               "declare the client's ip in topology"))
    elif fl["kind"] not in _MULTICAST_KINDS:  # unicast toward via/dst
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


def _check_pk4(spec: dict, fl: dict, kind: dict) -> list[dict]:
    fid, params = fl["id"], fl["params"]
    errs = sorted(Draft202012Validator(kind["params"]).iter_errors(params), key=lambda e: list(map(str, e.path)))
    out = [finding("PK4", f"{fid}: {e.message}", f"fix params for {fl['kind']}") for e in errs]
    if out:
        return out
    if fl["kind"] == "arp" and params["outcome"] == "gratuitous" and fl["dst"] != fl["src"]:
        out.append(finding("PK4", f"{fid}: gratuitous ARP must have dst == src", "set dst to the same endpoint as src"))
    if fl["kind"] == "cdp" and fl.get("vlan", 1) != 1:
        out.append(finding("PK4", f"{fid}: CDP rides VLAN 1", "drop the flow's vlan, or set it to 1"))
    if fl["kind"] == "cdp" and params["native_vlan"] != sender_native(spec, fl):
        out.append(finding("PK4", f"{fid}: CDP announces native VLAN {params['native_vlan']}, but the sender's trunk "
                                  f"native VLAN at {fl['t']} is {sender_native(spec, fl)}",
                           "announce the sender's native VLAN, or add the native-VLAN edit before the flow"))
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


def _events(spec: dict, fmt: str, device: str | None = None) -> list[dict]:
    return [e for e in spec.get("events", []) if e["format_id"] == fmt and (device is None or e["device"] == device)]


def _within(e: dict, t: datetime, after_s: float) -> bool:
    return t <= parse_utc(e["t"]) <= t + timedelta(seconds=after_s)


def _psecure_ok(spec: dict, fl: dict) -> bool:
    """A second MAC on a port-security port: src is attached to the monitored port and is logged as the violator."""
    cap = spec["capture"]
    att = (spec["topology"].get("entities", {}).get(fl["src"]) or {}).get("attached") or {}
    if att.get("device") != cap["device"] or short_if(att.get("interface")) != short_if(cap["interface"]):
        return False
    mac, t = parse_mac((resolve_endpoint(spec, fl["src"]) or {}).get("mac") or ""), parse_utc(fl["t"])
    return any(parse_mac(e["fields"].get("mac", "")) == mac and _within(e, t, 5)
               and short_if(e["fields"].get("interface")) == short_if(cap["interface"])
               for e in _events(spec, "IOS:PORT_SECURITY-2-PSECURE_VIOLATION", cap["device"]))


def _check_pk5_arp(spec: dict, fl: dict) -> list[dict]:
    """An ARP symptom is the port-security violator's frame, or an unanswered request on a VLAN the far end pruned."""
    if fl["kind"] != "arp" or fl["label"] != "symptom" or _psecure_ok(spec, fl):
        return []
    if fl["params"]["outcome"] != "no_reply":
        return [finding("PK5", f"{fl['id']}: only an unanswered ARP can be a symptom", "use outcome no_reply")]
    peer, vlan = spec["capture"]["peer"], flow_vlan(spec, fl)
    allowed = peer_allowed_vlans(spec, parse_utc(fl["t"]))
    if allowed is None or vlan in allowed:
        return [finding("PK5", f"{fl['id']}: no switchport trunk allowed vlan list on {peer} before {fl['t']} "
                               f"drops VLAN {vlan}",
                        f"add the trunk edit to config_diffs on {peer}, as a plain VLAN list")]
    return []


_BPDU_LINE = re.compile(r"^\s*spanning-tree bpdu(filter|guard)\b", re.MULTILINE)
_PK5_FIX = {
    "stp_bpdu": "add the guard-to-filter edit on {dev} {ifn} (spanning-tree bpdufilter enable) to config_diffs",
    "dhcp": "log ISCDHCPD:no-free-leases for the client's MAC within 30 s, or make it the port-security violator",
    "cdp": "announce a native VLAN unlike the near end's, and log IOS:CDP-4-NATIVE_VLAN_MISMATCH on {dev} within 60 s",
    "hsrp_hello": "log IOS:HSRP-5-STATECHANGE to this state on the sender for that group before the hello",
}


def _l2_symptom_ok(spec: dict, fl: dict) -> bool:
    cap, p, t = spec["capture"], fl["params"], parse_utc(fl["t"])
    kind = fl["kind"]
    if kind == "stp_bpdu":  # BPDUs arriving on an edge port that no longer guards against them
        after = stanza_decision(spec, t, cap["device"], cap["interface"], _BPDU_LINE)
        return after is not None and re.search(r"^\s*spanning-tree bpdufilter enable", after, re.MULTILINE) is not None
    if kind == "dhcp":
        if p["outcome"] != "no_offer":
            return False
        mac = parse_mac((resolve_endpoint(spec, fl["src"]) or {}).get("mac") or "")
        return _psecure_ok(spec, fl) or any(
            parse_mac(e["fields"].get("mac", "")) == mac and _within(e, t, span_s(fl) + 30)
            for e in _events(spec, "ISCDHCPD:no-free-leases"))
    if kind == "cdp":
        near = (cap.get("span") or {}).get("native_vlan", 1)
        return p["native_vlan"] != near and any(
            e["fields"].get("neighbor_vlan") == str(p["native_vlan"]) and e["fields"].get("local_vlan") == str(near)
            and _within(e, t, 60) for e in _events(spec, "IOS:CDP-4-NATIVE_VLAN_MISMATCH", cap["device"]))
    if kind == "hsrp_hello":  # the hello's state is the sender's latest logged state for that group
        host, _, ifn = fl["src"].partition(":")
        changes = sorted((parse_utc(e["t"]), e["fields"].get("new_state", "")) for e in
                         _events(spec, "IOS:HSRP-5-STATECHANGE", host)
                         if e["fields"].get("group") == str(p["group"])
                         and short_if(e["fields"].get("interface")) == short_if(ifn) and parse_utc(e["t"]) <= t)
        return bool(changes) and changes[-1][1].lower() == p["outcome"]
    return True


def _check_pk5_l2(spec: dict, fl: dict) -> list[dict]:
    if fl["label"] != "symptom" or fl["kind"] not in _PK5_FIX or _l2_symptom_ok(spec, fl):
        return []
    cap = spec["capture"]
    return [finding("PK5", f"{fl['id']}: the {fl['kind']} symptom at {fl['t']} isn't backed by the logs or configs",
                    _PK5_FIX[fl["kind"]].format(dev=cap["device"], ifn=cap["interface"]))]


def _check_pk8(spec: dict, fl: dict) -> list[dict]:
    cap = spec["capture"]
    if fl["label"] != "symptom":
        return []
    if not keeps(cap, flow_class(spec, fl)):
        return [finding("PK8", f"{fl['id']}: {method_label(cap)} on {cap['device']} can't see {fl['kind']} frames",
                        "pick a capture method that sees them")]
    down = port_down_at(spec)
    if down is not None and parse_utc(fl["t"]) >= down:
        return [finding("PK8", f"{fl['id']}: the monitored port is err-disabled from {down:%H:%M:%S}; nothing after "
                               "it is captured", "move the flow before the err-disable, or capture elsewhere")]
    return []


def _check_pk9_vlan(spec: dict, fl: dict) -> list[dict]:
    span = spec["capture"].get("span") or {}
    if span.get("encapsulation") != "replicate":
        return []
    vlan = flow_vlan(spec, fl)
    if vlan != span.get("native_vlan", 1) and vlan not in span["trunk_vlans"]:
        return [finding("PK9", f"{fl['id']}: VLAN {vlan} is not in capture.span.trunk_vlans",
                        "add it to trunk_vlans or fix the flow's VLAN")]
    return []


def _check_pk9(spec: dict, cap: dict) -> list[dict]:
    """The reason names the capture device; an ERSPAN session's analyzer, origin and via exist."""
    out = []
    if cap["device"] not in cap["reason"]:
        out.append(finding("PK9", f"capture.reason doesn't name {cap['device']}",
                           "say where the capture runs, e.g. 'Local SPAN on <device> <interface>: ...'"))
    e = cap.get("erspan")
    if not e:
        return out
    ana = spec["topology"].get("entities", {}).get(e["analyzer"])
    if ana is None or not ana.get("mac") or not ana.get("ip"):
        out.append(finding("PK9", f"capture.erspan.analyzer {e['analyzer']!r} is not an entity with a mac and ip",
                           "declare the analyzer under topology.entities with mac and ip"))
    dev = next((d for d in spec["topology"]["devices"] if d["hostname"] == cap["device"]), {})
    if e["origin_ip"] not in {i.get("ip") for i in dev.get("interfaces", [])}:
        out.append(finding("PK9", f"capture.erspan.origin_ip {e['origin_ip']} is not an ip on {cap['device']}",
                           f"use an interface ip of {cap['device']}"))
    if "via" in e and not (resolve_endpoint(spec, e["via"]) or {}).get("mac"):
        out.append(finding("PK9", f"capture.erspan.via {e['via']!r} doesn't resolve to an endpoint with a mac",
                           "use the gateway in front of the analyzer, e.g. HOST:IFNAME"))
    return out


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
