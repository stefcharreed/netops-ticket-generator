"""capture_<dev>_<if>.pcap: a synthetic SPAN capture (classic pcap, DLT_EN10MB).

The only module that imports dpkt (optional `capture` extra). The renderer assumes the
spec already passed validate(). Seam discipline: returns plain data, never prints.
"""
from __future__ import annotations

import ipaddress
import random
import re
import struct
from pathlib import Path

import dpkt

from packetgen.capture import capture_filename, resolve_endpoint
from packetgen.timebase import parse_utc

BCAST = b"\xff" * 6
STP_MC = bytes.fromhex("0180c2000000")
_ETH_IP, _ETH_ARP = 0x0800, 0x0806
_MIN_FRAME = 60
_NOISE_ARP_S = {"low": 30.0, "medium": 10.0, "high": 3.0}

# (ts, tiebreak, frame_bytes, pk_id or None); tiebreak = (group, flow index, sequence)
_Frame = tuple[float, tuple[int, int, int], bytes, "str | None"]


def mac_bytes(text: str) -> bytes:
    """Colon, dash or Cisco-dotted MAC text -> 6 bytes."""
    digits = re.sub(r"[:.\-]", "", text)
    if len(digits) != 12:
        raise ValueError(f"not a MAC address: {text!r}")
    return bytes.fromhex(digits)


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
            attrs = [(1, p["username"].encode()), (4, _ip4(sip)), (61, struct.pack(">I", 15)),
                     (31, cmac.encode()), (87, p["nas_port"].encode())]
            req = _radius(dpkt.radius.RADIUS_ACCESS_REQUEST, ident, auth, attrs)
            if p["outcome"] == "no_response":
                step = p.get("timeout_s", 5)
                out = [(t0 + step * i, fwd(sport, dport, req)) for i in range(p.get("retries", 3) + 1)]
            else:
                code = dpkt.radius.RADIUS_ACCESS_ACCEPT if p["outcome"] == "accept" else dpkt.radius.RADIUS_ACCESS_REJECT
                out = [(t0, fwd(sport, dport, req)),
                       (t0 + rng.uniform(0.002, 0.040), back(dport, sport, _radius(code, ident, rng.randbytes(16), [])))]
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
    return [(ts, (0, idx, n), buf, fl["id"]) for n, (ts, buf) in enumerate(out)]


def _bridge_id(mac: bytes) -> bytes:
    # Ceiling: real bridges use their base MAC; the peer_interface MAC stands in for it.
    return struct.pack(">H", 0x8000) + mac


def _bpdu(mac: bytes) -> bytes:
    """RSTP BPDU in 802.3 + LLC (42 42 03), version 2, root = this bridge."""
    body = struct.pack(">HBBB8sI8sHHHHH", 0, 2, 2, 0x3C, _bridge_id(mac), 0, _bridge_id(mac),
                       0x8001, 0, 20 * 256, 2 * 256, 15 * 256) + b"\x00"
    llc = b"\x42\x42\x03" + body
    return _pad(STP_MC + mac + struct.pack(">H", len(llc)) + llc)


def _noise_frames(ctx: _Ctx, cap: dict, lo: float, hi: float) -> list[_Frame]:
    level = cap.get("noise", "medium")
    rng = random.Random(f"{ctx.meta_id}:noise")
    out: list[tuple[float, bytes]] = []
    topo = ctx.spec["topology"]
    if level in ("medium", "high"):
        peer = next(d for d in topo["devices"] if d["hostname"] == cap["peer"])
        pmac = mac_bytes(next(i for i in peer["interfaces"] if i["name"] == cap["peer_interface"])["mac"])
        k = 0
        while lo + 2.0 * k < hi:
            out.append((lo + 2.0 * k, _bpdu(pmac)))
            k += 1
    # ARP pairs among declared hosts in a /24 that the capture device or its peer sits in.
    # Ceiling: the pair choice ignores which side of the SPAN port each host sits on.
    hosts = [e for e in topo.get("entities", {}).values() if e.get("mac") and e.get("ip")]
    hosts += [i for dv in topo["devices"] for i in dv.get("interfaces", []) if i.get("mac") and i.get("ip")]
    anchors = {ipaddress.ip_network(f"{i['ip']}/24", strict=False) for dv in topo["devices"]
               if dv["hostname"] in (cap["device"], cap["peer"]) for i in dv.get("interfaces", []) if i.get("ip")}
    hosts = [h for h in hosts if ipaddress.ip_network(f"{h['ip']}/24", strict=False) in anchors]
    step = _NOISE_ARP_S[level]
    k = 1
    while len(hosts) >= 2 and lo + step * k < hi - 0.01:
        a, b = rng.sample(hosts, 2)
        am, bm = mac_bytes(a["mac"]), mac_bytes(b["mac"])
        t = lo + step * k
        out.append((t, _eth(BCAST, am, _ETH_ARP, _arp(dpkt.arp.ARP_OP_REQUEST, am, a["ip"], b"\x00" * 6, b["ip"]))))
        out.append((t + rng.uniform(0.0005, 0.005),
                    _eth(am, bm, _ETH_ARP, _arp(dpkt.arp.ARP_OP_REPLY, bm, b["ip"], am, a["ip"]))))
        k += 1
    return [(ts, (1, 0, n), buf, None) for n, (ts, buf) in enumerate(out)]


def build_frames(spec: dict) -> tuple[list[tuple[float, bytes]], dict[str, list[int]]]:
    """All frames sorted by (ts, tiebreak), plus pk id -> 1-based frame numbers (labeled flows only)."""
    cap = spec["capture"]
    ctx = _Ctx(spec)
    lo, hi = parse_utc(cap["start"]).timestamp(), parse_utc(cap["end"]).timestamp()
    allf: list[_Frame] = []
    for idx, fl in enumerate(cap["flows"]):
        allf += _flow_frames(ctx, fl, idx)
    allf += _noise_frames(ctx, cap, lo, hi)
    allf = [(round(ts, 6), tb, buf, pk) for ts, tb, buf, pk in allf]  # pcap has microsecond resolution
    allf.sort(key=lambda f: (f[0], f[1]))
    pk_map: dict[str, list[int]] = {}
    for n, (_, _, _, pk) in enumerate(allf, start=1):
        if pk is not None:
            pk_map.setdefault(pk, []).append(n)
    return [(ts, buf) for ts, _, buf, _ in allf], pk_map


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
