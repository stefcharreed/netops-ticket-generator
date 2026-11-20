"""capture_<dev>_<if>.pcap: a synthetic SPAN capture (classic pcap, DLT_EN10MB).

The only module that imports dpkt (optional `capture` extra). The renderer assumes the
spec already passed validate(). Seam discipline: returns plain data, never prints.
"""
from __future__ import annotations

import ipaddress
import random
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

import dpkt

from packetgen.capture import (capture_filename, parse_mac, peer_allowed_vlans, peer_native_vlan, port_down_at,
                               resolve_endpoint)
from packetgen.topology import short_if
from packetgen.capture_views import flow_class, flow_vlan, keeps, sender_native, tagged
from packetgen.timebase import parse_utc

BCAST = b"\xff" * 6
STP_MC = bytes.fromhex("0180c2000000")
SSTP_MC = bytes.fromhex("01000ccccccd")  # Cisco PVST+ shared spanning tree protocol
_SNAP_PVST = bytes.fromhex("aaaa0300000c010b")
CDP_MC = bytes.fromhex("01000ccccccc")
_SNAP_CDP = bytes.fromhex("aaaa0300000c2000")
HSRP_MC = bytes.fromhex("01005e000002")
_ETH_IP, _ETH_ARP = 0x0800, 0x0806
_MIN_FRAME = 60
_NOISE_ARP_S = {"low": 30.0, "medium": 10.0, "high": 3.0}



class _Frame(NamedTuple):
    """A stage-1 frame: untagged bytes plus what the per-method view needs. tb = (group, flow index, sequence)."""
    ts: float
    tb: tuple[int, int, int]
    buf: bytes
    pk: str | None
    vlan: int
    fclass: str
    native: int  # the sender's native VLAN: frames in it leave its trunk untagged


def mac_bytes(text: str) -> bytes:
    """Colon, dash or Cisco-dotted MAC text -> 6 bytes."""
    mac = parse_mac(text)
    if mac is None:
        raise ValueError(f"not a MAC address: {text!r}")
    return mac


def _pad(buf: bytes) -> bytes:
    return buf + b"\x00" * (_MIN_FRAME - len(buf)) if len(buf) < _MIN_FRAME else buf


def _eth(dst: bytes, src: bytes, etype: int, data: bytes) -> bytes:
    return _pad(bytes(dpkt.ethernet.Ethernet(dst=dst, src=src, type=etype, data=data)))


def _ip4(text: str) -> bytes:
    return ipaddress.IPv4Address(text).packed


def _ipv4_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, ttl: int, ipid: int) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, ulen=8 + len(payload), data=payload)
    ip = dpkt.ip.IP(src=_ip4(src_ip), dst=_ip4(dst_ip), p=dpkt.ip.IP_PROTO_UDP, ttl=ttl, id=ipid,
                    len=20 + 8 + len(payload), data=udp)
    return bytes(ip)  # dpkt fills the IP and UDP checksums


def _radius(code: int, ident: int, auth: bytes, attrs: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(struct.pack("BB", t, len(v) + 2) + v for t, v in attrs)
    return bytes(dpkt.radius.RADIUS(code=code, id=ident, len=20 + len(body), auth=auth, data=body))


def _arp(op: int, sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    return bytes(dpkt.arp.ARP(sha=sha, spa=_ip4(spa), tha=tha, tpa=_ip4(tpa), op=op))


class _Ctx:
    """Per-capture state: topology lookups and per-sender IP id counters."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.meta_id = spec["meta"]["id"]
        self._ipid: dict[str, int] = {}

    def ipid(self, sender: str) -> int:
        if sender not in self._ipid:
            self._ipid[sender] = random.Random(f"{self.meta_id}:ipid:{sender}").randrange(0x10000)
        self._ipid[sender] = (self._ipid[sender] + 1) & 0xFFFF
        return self._ipid[sender]

    def is_entity(self, name: str) -> bool:
        return name in self.spec["topology"].get("entities", {})

    def ep(self, name: str) -> dict:
        ep = resolve_endpoint(self.spec, name)
        if ep is None:
            raise ValueError(f"endpoint {name!r} doesn't resolve (run validate first)")
        return ep


def _need_mac(ep: dict, name: str) -> bytes:
    if not ep["mac"]:
        raise ValueError(f"{name!r} has no mac (run validate first)")
    return mac_bytes(ep["mac"])


def _arp_frames(ctx: _Ctx, fl: dict, rng: random.Random, t0: float) -> list[tuple[float, bytes]]:
    p, src, dst = fl["params"], fl["src"], fl["dst"]
    s, d = ctx.ep(src), ctx.ep(dst)
    smac = _need_mac(s, src)
    outcome = p["outcome"]
    tpa = s["ip"] if outcome == "gratuitous" else d["ip"]
    n = p.get("retries", 2) + 1 if outcome == "no_reply" else 1
    out = [(t0 + 1.0 * i, _eth(BCAST, smac, _ETH_ARP, _arp(dpkt.arp.ARP_OP_REQUEST, smac, s["ip"], b"\x00" * 6, tpa)))
           for i in range(n)]
    if outcome == "reply":
        dmac = _need_mac(d, dst)
        rep = _arp(dpkt.arp.ARP_OP_REPLY, dmac, d["ip"], smac, s["ip"])
        out.append((t0 + rng.uniform(0.0005, 0.005), _eth(smac, dmac, _ETH_ARP, rep)))
    return out


def _flow_frames(ctx: _Ctx, fl: dict, idx: int) -> list[_Frame]:
    rng = random.Random(f"{ctx.meta_id}:{fl['id']}")
    t0 = parse_utc(fl["t"]).timestamp()
    p = fl["params"]
    src, dst, via = fl["src"], fl["dst"], fl.get("via")

    if fl["kind"] == "arp":  # link-local: via plays no part
        out = _arp_frames(ctx, fl, rng, t0)
    elif fl["kind"] in _L2_BUILDERS:
        out = _L2_BUILDERS[fl["kind"]](ctx, fl, rng, t0)
    else:
        s, d = ctx.ep(src), ctx.ep(dst)
        smac, dmac = _need_mac(s, src), _need_mac(d, dst)
        hop = _need_mac(ctx.ep(via), via) if via else None
        fwd_dst = back_src = hop or dmac  # routed replies leave the gateway, not the server
        ttl_f = 64 if ctx.is_entity(src) else 255
        ttl_b = (64 if ctx.is_entity(dst) else 255) - (1 if via else 0)  # replies crossed via
        sip, dip = s["ip"], d["ip"]

        def fwd(sport: int, dport: int, payload: bytes) -> bytes:
            return _eth(fwd_dst, smac, _ETH_IP, _ipv4_udp(sip, dip, sport, dport, payload, ttl_f, ctx.ipid(src)))

        def back(sport: int, dport: int, payload: bytes) -> bytes:
            return _eth(smac, back_src, _ETH_IP, _ipv4_udp(dip, sip, sport, dport, payload, ttl_b, ctx.ipid(dst)))

        out = []
        if fl["kind"] == "radius_request":
            sport = rng.randrange(21645, 21845)
            ident, auth = rng.randrange(256), rng.randbytes(16)
            dport = p.get("auth_port", 1812)
            cmac = "-".join(f"{b:02X}" for b in mac_bytes(ctx.ep(p["client"])["mac"]))
            user = p["username"].encode()
            eap_id = rng.randrange(256)
            # 802.1X shape (RFC 2865/3579/3580). Ceiling: Message-Authenticator is random bytes, not an HMAC-MD5.
            attrs = [(1, user), (4, _ip4(sip)), (5, struct.pack(">I", rng.randrange(1, 0x10000))),
                     (6, struct.pack(">I", 2)), (12, struct.pack(">I", 1485)), (31, cmac.encode()),
                     (61, struct.pack(">I", 15)), (87, p["nas_port"].encode()),
                     (79, struct.pack(">BBHB", 2, eap_id, 5 + len(user), 1) + user),  # EAP-Response/Identity
                     (80, rng.randbytes(16))]
            req = _radius(dpkt.radius.RADIUS_ACCESS_REQUEST, ident, auth, attrs)
            if p["outcome"] == "no_response":
                step = p.get("timeout_s", 5)
                out = [(t0 + step * i, fwd(sport, dport, req)) for i in range(p.get("retries", 3) + 1)]
            else:
                ok = p["outcome"] == "accept"
                code = dpkt.radius.RADIUS_ACCESS_ACCEPT if ok else dpkt.radius.RADIUS_ACCESS_REJECT
                eap = struct.pack(">BBH", 3 if ok else 4, eap_id, 4)  # EAP-Success / EAP-Failure
                reply = _radius(code, ident, rng.randbytes(16), [(79, eap), (80, rng.randbytes(16))])
                out = [(t0, fwd(sport, dport, req)), (t0 + rng.uniform(0.002, 0.040), back(dport, sport, reply))]
        else:  # dns_query
            sport, txid = rng.randrange(49152, 65536), rng.randrange(0x10000)
            qtype = dpkt.dns.DNS_AAAA if p.get("qtype", "A") == "AAAA" else dpkt.dns.DNS_A
            qd = [dpkt.dns.DNS.Q(name=p["name"], type=qtype)]
            q = bytes(dpkt.dns.DNS(id=txid, op=dpkt.dns.DNS_RD, qd=qd))
            if p["outcome"] == "timeout":
                out = [(t0 + 2.0 * i, fwd(sport, 53, q)) for i in range(p.get("retries", 1) + 1)]
            else:
                rcode = {"ok": dpkt.dns.DNS_RCODE_NOERR, "nxdomain": dpkt.dns.DNS_RCODE_NXDOMAIN,
                         "servfail": dpkt.dns.DNS_RCODE_SERVFAIL}[p["outcome"]]
                an = []
                if p["outcome"] == "ok":
                    an = [dpkt.dns.DNS.RR(name=p["name"], type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=300,
                                          ip=_ip4(ctx.ep(p["answer"])["ip"]))]
                resp = bytes(dpkt.dns.DNS(id=txid, op=dpkt.dns.DNS_QR | dpkt.dns.DNS_RD | dpkt.dns.DNS_RA,
                                          rcode=rcode, qd=qd, an=an))
                out = [(t0, fwd(sport, 53, q)), (t0 + rng.uniform(0.002, 0.040), back(53, sport, resp))]
    vlan, fclass, native = flow_vlan(ctx.spec, fl), flow_class(ctx.spec, fl), sender_native(ctx.spec, fl)
    return [_Frame(ts, (0, idx, n), buf, fl["id"], vlan, fclass, native) for n, (ts, buf) in enumerate(out)]


def _bridge_id(mac: bytes, vlan: int = 1) -> bytes:
    # Ceiling: real bridges use their base MAC; the peer_interface MAC stands in for it.
    return struct.pack(">H", 0x8000 + vlan) + mac  # priority 32768 + sys-id-ext (the VLAN)


def _rstp_body(mac: bytes, vlan: int, flags: int = 0x3C) -> bytes:
    """RSTP BPDU body, version 2, root = this bridge. flags 0x3C: designated, learning, forwarding (+0x01 TC)."""
    return struct.pack(">HBBB8sI8sHHHHH", 0, 2, 2, flags, _bridge_id(mac, vlan), 0, _bridge_id(mac, vlan),
                       0x8001, 0, 20 * 256, 2 * 256, 15 * 256) + b"\x00"


def _bpdu(mac: bytes, vlan: int = 1, flags: int = 0x3C) -> bytes:
    """IEEE RSTP BPDU in 802.3 + LLC (42 42 03): the native VLAN's untagged copy."""
    llc = b"\x42\x42\x03" + _rstp_body(mac, vlan, flags)
    return _pad(STP_MC + mac + struct.pack(">H", len(llc)) + llc)


def _sstp(mac: bytes, vlan: int, flags: int = 0x3C) -> bytes:
    """Rapid-PVST+ SSTP BPDU: 802.3 + LLC/SNAP (Cisco, PID 0x010b), RSTP body, PVID TLV."""
    llc = _SNAP_PVST + _rstp_body(mac, vlan, flags) + struct.pack(">HHH", 0, 2, vlan)
    return _pad(SSTP_MC + mac + struct.pack(">H", len(llc)) + llc)


def _periodic(fl: dict, rng: random.Random, t0: float, count: int, interval: int) -> list[float]:
    """count send times interval_s apart; the first at exactly t, the rest with +-5 ms seeded jitter."""
    p = fl["params"]
    n, step = p.get("count", count), p.get("interval_s", interval)
    return [t0] + [t0 + step * i + rng.uniform(-0.005, 0.005) for i in range(1, n)]


def _stp_frames(ctx: _Ctx, fl: dict, rng: random.Random, t0: float) -> list[tuple[float, bytes]]:
    smac, vlan = _need_mac(ctx.ep(fl["src"]), fl["src"]), flow_vlan(ctx.spec, fl)
    flags = 0x3D if fl["params"]["outcome"] == "topology_change" else 0x3C
    build = _sstp if fl["params"].get("proto", "ieee") == "pvst" else _bpdu
    return [(ts, build(smac, vlan, flags)) for ts in _periodic(fl, rng, t0, 10, 2)]


def _cdp_frames(ctx: _Ctx, fl: dict, rng: random.Random, t0: float) -> list[tuple[float, bytes]]:
    p = fl["params"]
    smac = _need_mac(ctx.ep(fl["src"]), fl["src"])
    tlvs = [(dpkt.cdp.CDP_DEVID, p["device_id"].encode()), (dpkt.cdp.CDP_PORTID, p["port_id"].encode()),
            (dpkt.cdp.CDP_CAPABILITIES, struct.pack(">I", 0x28)),  # switch, IGMP
            (dpkt.cdp.CDP_NATIVE_VLAN, struct.pack(">H", p["native_vlan"]))]
    body = b"".join(bytes(dpkt.cdp.CDP.TLV(type=t, len=4 + len(v), data=v)) for t, v in tlvs)
    cdp = dpkt.cdp.CDP(version=2, ttl=180, data=body)  # dpkt 1.9.8 packs .data, not .tlvs
    llc = _SNAP_CDP + bytes(cdp)  # dpkt fills the RFC 1071 checksum over the CDP payload
    frame = _pad(CDP_MC + smac + struct.pack(">H", len(llc)) + llc)
    return [(ts, frame) for ts in _periodic(fl, rng, t0, 1, 60)]


def _hsrp_frames(ctx: _Ctx, fl: dict, rng: random.Random, t0: float) -> list[tuple[float, bytes]]:
    p = fl["params"]
    s = ctx.ep(fl["src"])
    state = {"active": 16, "standby": 8, "speak": 4}[p["outcome"]]
    # HSRPv1 (RFC 2281): the Active router sources hellos from the group's virtual MAC.
    smac = bytes.fromhex(f"00000c07ac{p['group']:02x}") if state == 16 else _need_mac(s, fl["src"])
    hello = bytes(dpkt.hsrp.HSRP(version=0, opcode=0, state=state, hello=3, hold=10, priority=p.get("priority", 100),
                                 group=p["group"], rsvd=0, auth=b"cisco\x00\x00\x00", vip=_ip4(p["vip"])))
    return [(ts, _eth(HSRP_MC, smac, _ETH_IP, _ipv4_udp(s["ip"], "224.0.0.2", 1985, 1985, hello, 1,
                                                    ctx.ipid(fl["src"]))))
            for ts in _periodic(fl, rng, t0, 5, 3)]


def _dhcp(op: int, xid: int, chaddr: bytes, mtype: int, opts: list[tuple[int, bytes]], yiaddr: str = "0.0.0.0",
          giaddr: str = "0.0.0.0") -> bytes:
    return bytes(dpkt.dhcp.DHCP(op=op, xid=xid, chaddr=chaddr + b"\x00" * 10,
                                yiaddr=int(ipaddress.IPv4Address(yiaddr)), giaddr=int(ipaddress.IPv4Address(giaddr)),
                                opts=[(dpkt.dhcp.DHCP_OPT_MSGTYPE, bytes([mtype]))] + opts))


def _dhcp_frames(ctx: _Ctx, fl: dict, rng: random.Random, t0: float) -> list[tuple[float, bytes]]:
    p = fl["params"]
    c, srv, relay = ctx.ep(fl["src"]), ctx.ep(fl["dst"]), ctx.ep(fl["via"])
    cmac, rmac = _need_mac(c, fl["src"]), _need_mac(relay, fl["via"])
    xid = rng.randrange(2**32)
    cid = [(dpkt.dhcp.DHCP_OPT_CLIENT_ID, b"\x01" + cmac), (dpkt.dhcp.DHCP_OPT_PARAM_REQ, bytes([1, 3, 6, 15]))]

    def bcast(mtype: int, extra: list[tuple[int, bytes]]) -> bytes:
        body = _dhcp(dpkt.dhcp.DHCP_OP_REQUEST, xid, cmac, mtype, cid + extra)
        return _eth(BCAST, cmac, _ETH_IP, _ipv4_udp("0.0.0.0", "255.255.255.255", 68, 67, body, 64, ctx.ipid(fl["src"])))

    def reply(mtype: int) -> bytes:  # relayed back from the client VLAN's gateway
        sid = [(dpkt.dhcp.DHCP_OPT_SERVER_ID, _ip4(srv["ip"]))]
        body = _dhcp(dpkt.dhcp.DHCP_OP_REPLY, xid, cmac, mtype, sid, yiaddr=c["ip"], giaddr=relay["ip"])
        return _eth(cmac, rmac, _ETH_IP, _ipv4_udp(relay["ip"], c["ip"], 67, 68, body, 255, ctx.ipid(fl["via"])))

    if p["outcome"] == "no_offer":
        base = [(t0 + 4.0 * i, bcast(dpkt.dhcp.DHCPDISCOVER, [])) for i in range(p.get("retries", 3) + 1)]
    else:
        t_off = t0 + rng.uniform(0.002, 0.020)
        t_ack = t_off + 0.005 + rng.uniform(0.002, 0.020)
        req = [(dpkt.dhcp.DHCP_OPT_REQ_IP, _ip4(c["ip"])), (dpkt.dhcp.DHCP_OPT_SERVER_ID, _ip4(srv["ip"]))]
        base = [(t0, bcast(dpkt.dhcp.DHCPDISCOVER, [])), (t_off, reply(dpkt.dhcp.DHCPOFFER)),
                (t_off + 0.005, bcast(dpkt.dhcp.DHCPREQUEST, req)), (t_ack, reply(dpkt.dhcp.DHCPACK))]
    out = []
    for ts, frame in base:  # a loop replays every frame within a couple of milliseconds
        t = ts
        for _ in range(p.get("copies", 1)):
            out.append((t, frame))
            t += rng.uniform(0.0002, 0.002)
    return out


_L2_BUILDERS = {"stp_bpdu": _stp_frames, "cdp": _cdp_frames, "hsrp_hello": _hsrp_frames, "dhcp": _dhcp_frames}


def _noise_frames(ctx: _Ctx, cap: dict, lo: float, hi: float) -> list[_Frame]:
    level = cap.get("noise", "medium")
    rng = random.Random(f"{ctx.meta_id}:noise")
    native = cap.get("span", {}).get("native_vlan", 1)
    out: list[tuple[float, bytes, int, str, int]] = []  # (ts, frame, vlan, fclass, sender native)
    topo = ctx.spec["topology"]
    peer = next((d for d in topo["devices"] if d["hostname"] == cap["peer"]), None)
    access = peer is None  # an entity peer: the monitored port is an access port
    if level in ("medium", "high") and peer is not None:  # an entity peer (a PC, a hub) sends no BPDUs
        pmac = mac_bytes(next(i for i in peer["interfaces"] if i["name"] == cap["peer_interface"])["mac"])
        vlans = cap.get("span", {}).get("trunk_vlans", [native])
        phase, k = rng.uniform(0.0, 2.0), 0
        # Rapid-PVST+: per tick, the native VLAN's IEEE + SSTP pair, then one tagged SSTP per other trunk VLAN.
        # Ceiling: the near end never takes over as root for a VLAN the peer pruned.
        while lo + phase + 2.0 * k < hi - 0.01:  # margin keeps the +-5 ms jitter inside the window
            t = max(lo, lo + phase + 2.0 * k + rng.uniform(-0.005, 0.005))
            when = datetime.fromtimestamp(t, timezone.utc)
            allowed = peer_allowed_vlans(ctx.spec, when)
            pnat = peer_native_vlan(ctx.spec, when) or native  # the far end tags against its own native VLAN
            for v in vlans:
                if allowed is not None and v not in allowed:
                    continue
                if v == pnat:  # IEEE BPDU rides untagged with the native VLAN's SSTP (assumed for pnat != 1)
                    out.append((t, _bpdu(pmac), v, "l2_control", pnat))
                out.append((t, _sstp(pmac, v), v, "l2_control", pnat))
            k += 1
    # ARP pairs among declared hosts in a /24 that the capture device or its peer sits in.
    # Ceiling: the pair choice ignores which side of the SPAN port each host sits on.
    hosts = [e for e in topo.get("entities", {}).values() if e.get("mac") and e.get("ip")]
    hosts += [i for dv in topo["devices"] for i in dv.get("interfaces", []) if i.get("mac") and i.get("ip")]
    anchors = {ipaddress.ip_network(f"{i['ip']}/24", strict=False) for dv in topo["devices"]
               if dv["hostname"] in (cap["device"], cap["peer"]) for i in dv.get("interfaces", []) if i.get("ip")}
    hosts = [h for h in hosts if ipaddress.ip_network(f"{h['ip']}/24", strict=False) in anchors]
    step = _NOISE_ARP_S[level]
    phase, k = rng.uniform(0.0, 1.0), 1
    while len(hosts) >= 2 and lo + phase + step * (k - 0.4) < hi - 0.01:
        a, b = rng.sample(hosts, 2)
        am, bm = mac_bytes(a["mac"]), mac_bytes(b["mac"])
        vlan = _host_vlan(a) or native
        t = lo + phase + step * k + rng.uniform(-0.4, 0.4) * step
        k += 1
        if t >= hi - 0.01:  # jitter pushed it past the window end: skip this tick
            continue
        allowed = peer_allowed_vlans(ctx.spec, datetime.fromtimestamp(t, timezone.utc))
        if allowed is not None and {_host_vlan(a) or native, _host_vlan(b) or native} - allowed:
            continue  # a VLAN the far end pruned can't carry a request and its answer across the trunk
        out.append((t, _eth(BCAST, am, _ETH_ARP, _arp(dpkt.arp.ARP_OP_REQUEST, am, a["ip"], b"\x00" * 6, b["ip"])),
                    vlan, "data", native))
        if access and not _on_port(a, cap):
            continue  # an access port sees the broadcast, but the unicast answer goes to a host elsewhere
        out.append((t + rng.uniform(0.0005, 0.005),
                    _eth(am, bm, _ETH_ARP, _arp(dpkt.arp.ARP_OP_REPLY, bm, b["ip"], am, a["ip"])), vlan, "data", native))
    return [_Frame(ts, (1, 0, n), buf, None, vlan, fc, nat) for n, (ts, buf, vlan, fc, nat) in enumerate(out)]


def _on_port(h: dict, cap: dict) -> bool:
    """Whether a host (entity) is attached to the monitored port."""
    att = h.get("attached") or {}
    return att.get("device") == cap["device"] and short_if(att.get("interface")) == short_if(cap["interface"])


def _host_vlan(h: dict) -> int | None:
    """An entity's attached VLAN or an interface's VLAN."""
    return (h.get("attached") or {}).get("vlan") or h.get("vlan")


def _dot1q(buf: bytes, vlan: int) -> bytes:
    """Insert an 802.1Q tag (TPID 0x8100, PCP 0) after the MAC addresses."""
    return buf[:12] + struct.pack(">HH", 0x8100, vlan & 0xFFF) + buf[12:]


def _erspan(ctx: _Ctx, cap: dict, buf: bytes, vlan: int, seq: int) -> bytes:
    """ERSPAN type II: outer Ethernet / IPv4 proto 47 / GRE (S bit, 0x88BE) / 8-byte ERSPAN header / inner frame."""
    e = cap["erspan"]
    ana = ctx.ep(e["analyzer"])
    if "via" in e:
        src_mac = _need_mac(ctx.ep(e["via"]), e["via"])
    else:
        dev = next(d for d in ctx.spec["topology"]["devices"] if d["hostname"] == cap["device"])
        src_mac = mac_bytes(next(i for i in dev["interfaces"] if i.get("ip") == e["origin_ip"])["mac"])
    # version 1 | VLAN; COS 0, En 00 (untagged inner frame, assumed), T 0 | session id; reserved + index 0
    hdr = struct.pack(">HHI", (1 << 12) | (vlan & 0xFFF), e["erspan_id"] & 0x3FF, 0)
    gre = struct.pack(">HHI", 0x1000, 0x88BE, seq) + hdr + buf
    ttl = 254 if "via" in e else 255  # ceiling: one routed hop when via is set
    ip = dpkt.ip.IP(src=_ip4(e["origin_ip"]), dst=_ip4(ana["ip"]), p=47, ttl=ttl, id=ctx.ipid(cap["device"]),
                    len=20 + len(gre), data=gre)
    return _eth(_need_mac(ana, e["analyzer"]), src_mac, _ETH_IP, bytes(ip))


def build_frames(spec: dict) -> tuple[list[tuple[float, bytes]], dict[str, list[int]]]:
    """All frames sorted by (ts, tiebreak), plus pk id -> 1-based frame numbers (labeled flows only)."""
    cap = spec["capture"]
    ctx = _Ctx(spec)
    lo, hi = parse_utc(cap["start"]).timestamp(), parse_utc(cap["end"]).timestamp()
    allf: list[_Frame] = []
    for idx, fl in enumerate(cap["flows"]):
        allf += _flow_frames(ctx, fl, idx)
    allf += _noise_frames(ctx, cap, lo, hi)
    allf = [f._replace(ts=round(f.ts, 6)) for f in allf]  # pcap has microsecond resolution
    allf.sort(key=lambda f: (f.ts, f.tb))
    down = port_down_at(spec)  # an err-disabled source port carries nothing more
    cut = down.timestamp() if down else float("inf")
    kept = [f for f in allf if keeps(cap, f.fclass) and f.ts < cut]  # stage 2: what this capture method can see
    seq = random.Random(f"{ctx.meta_id}:erspan").randrange(2**32)
    out: list[tuple[float, bytes]] = []
    pk_map: dict[str, list[int]] = {}
    for n, f in enumerate(kept, start=1):
        if cap["method"] == "erspan":
            buf = _erspan(ctx, cap, f.buf, f.vlan, (seq + n - 1) % 2**32)
        else:
            buf = _dot1q(f.buf, f.vlan) if tagged(cap, f.vlan, f.native) else f.buf
        out.append((f.ts, buf))
        if f.pk is not None:
            pk_map.setdefault(f.pk, []).append(n)
    return out, pk_map


def render_capture(spec: dict, out: Path) -> dict[str, list[int]]:
    """Write `out / capture_filename(spec)`; returns the pk id -> frame numbers map."""
    frames, pk_map = build_frames(spec)
    out.mkdir(parents=True, exist_ok=True)
    with (out / capture_filename(spec)).open("wb") as f:
        w = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in frames:
            w.writepkt(buf, ts=ts)
    return pk_map


def frame_count(path: Path) -> int:
    """Number of packets in a classic pcap file."""
    with path.open("rb") as f:
        return sum(1 for _ in dpkt.pcap.Reader(f))
