import copy
import ipaddress
import json
from pathlib import Path

import pytest

dpkt = pytest.importorskip("dpkt")

from packetgen.capture import capture_filename  # noqa: E402
from packetgen.render.capture import build_frames, mac_bytes, render_capture  # noqa: E402
from packetgen.timebase import parse_utc  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "radius_capture.json"
STP = bytes.fromhex("0180c2000000")


@pytest.fixture
def spec():
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def rep(spec):
    """The fixture as a replicate SPAN: BPDUs reach the analyzer."""
    spec["capture"]["span"] = {"encapsulation": "replicate", "trunk_vlans": [1]}
    return spec


def _erspan_spec(spec, via=True):
    spec["topology"]["entities"]["analyzer-1"] = {"ip": "10.30.0.5", "mac": "00:00:5e:00:53:30"}
    cap = spec["capture"]
    cap["method"] = "erspan"
    del cap["span"]
    cap["erspan"] = {"origin_ip": "10.10.100.2", "analyzer": "analyzer-1", "session": 1, "erspan_id": 100}
    if via:
        cap["erspan"]["via"] = "DIST-SW1:Vlan100"
    return spec


def _udp(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    return eth, eth.data, eth.data.data


def test_mac_notations():
    want = bytes.fromhex("00005e005301")
    assert mac_bytes("00:00:5e:00:53:01") == want
    assert mac_bytes("00-00-5E-00-53-01") == want
    assert mac_bytes("0000.5e00.5301") == want


def test_pk1_frames(spec):
    frames, pk = build_frames(spec)
    nums = pk["pk1"]
    assert len(nums) == 4
    ts = [frames[n - 1][0] for n in nums]
    assert [round(b - a, 6) for a, b in zip(ts, ts[1:])] == [5.0] * 3
    ids, sports = set(), set()
    for n in nums:
        eth, ip, udp = _udp(frames[n - 1][1])
        assert udp.dport == 1812
        assert str(ipaddress.IPv4Address(ip.dst)) == "10.20.0.10"
        assert eth.dst == bytes.fromhex("00005e005302")
        r = dpkt.radius.RADIUS(udp.data)
        ids.add(r.id)
        sports.add(udp.sport)
    assert len(ids) == 1 and len(sports) == 1


def test_deterministic(spec):
    assert build_frames(spec) == build_frames(copy.deepcopy(spec))


def test_frames_inside_window(spec):
    frames, _ = build_frames(spec)
    lo, hi = parse_utc(spec["capture"]["start"]).timestamp(), parse_utc(spec["capture"]["end"]).timestamp()
    assert all(lo <= ts <= hi for ts, _ in frames)
    assert [ts for ts, _ in frames] == sorted(ts for ts, _ in frames)


def test_min_frame_len(spec):
    frames, _ = build_frames(spec)
    assert all(len(b) >= 60 for _, b in frames)


def _bpdu_times(spec):
    frames, _ = build_frames(spec)
    return [ts for ts, b in frames if b[:6] == STP], frames


def test_native_span_drops_bpdus(spec):
    times, _ = _bpdu_times(spec)
    assert times == []


def test_noise_medium_has_bpdus(rep):
    times, _ = _bpdu_times(rep)
    assert abs(len(times) - 300) <= 1  # 600 s at 2 s, less the seeded phase offset


def test_bpdu_phase_and_jitter(rep):
    spec = rep
    times, _ = _bpdu_times(spec)
    lo = parse_utc(spec["capture"]["start"]).timestamp()
    assert 0.0 <= times[0] - lo < 2.01
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert all(1.989 <= g <= 2.011 for g in gaps)  # 2 s +- 2 x 5 ms
    assert len({round(g, 4) for g in gaps}) > 50  # jittered, not a metronome
    spec2 = copy.deepcopy(spec)
    spec2["meta"]["id"] = "pkt-aaaaaa"
    assert (_bpdu_times(spec2)[0][0] - lo) != (times[0] - lo)  # phase is seeded per packet id


def test_bpdu_bridge_priority_includes_vlan1_ext(rep):
    _, frames = _bpdu_times(rep)
    bpdu = next(b for _, b in frames if b[:6] == STP)
    assert bpdu[22:24] == bytes.fromhex("8001") and bpdu[34:36] == bytes.fromhex("8001")


def test_noise_arp_is_jittered(spec):
    frames, pk = build_frames(spec)
    owned = {n for nums in pk.values() for n in nums}
    reqs = [ts for n, (ts, b) in enumerate(frames, 1)
            if n not in owned and b[:6] == b"\xff" * 6 and b[12:14] == b"\x08\x06"]
    gaps = [b - a for a, b in zip(reqs, reqs[1:])]
    assert len(reqs) >= 50
    assert all(2.0 - 0.001 <= g <= 18.0 + 0.001 for g in gaps)  # interval 10 s, +-40% each tick
    assert len({round(g, 2) for g in gaps}) > 20
    assert any(abs(ts - round(ts)) > 0.05 for ts in reqs)  # sub-second offsets


def test_noise_low_has_no_bpdus(rep):
    rep["capture"]["noise"] = "low"
    frames, _ = build_frames(rep)
    assert not any(b[:6] == STP for _, b in frames)


def test_same_instant_order_stable(spec):
    flows = spec["capture"]["flows"]
    a = copy.deepcopy(flows[3])
    b = copy.deepcopy(flows[3])
    a["id"], b["id"] = "pkx", "pky"
    a["t"] = b["t"] = "2026-10-20T14:08:00Z"
    b["src"], b["dst"] = "pc-18", "printer-7"
    flows[:] = [flows[0], b, a]
    _, pk = build_frames(spec)
    assert pk["pky"][0] < pk["pkx"][0]


def test_flow_kinds_decode(spec):
    frames, pk = build_frames(spec)
    _, ip, udp = _udp(frames[pk["pk2"][1] - 1][1])
    assert dpkt.radius.RADIUS(udp.data).code == dpkt.radius.RADIUS_ACCESS_ACCEPT
    dns = dpkt.dns.DNS(_udp(frames[pk["pk3"][1] - 1][1])[2].data)
    assert dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN
    assert len(pk["pk4"]) == 3  # no_reply: retries 2 -> 3 requests
    assert dpkt.ethernet.Ethernet(frames[pk["pk4"][0] - 1][1]).dst == b"\xff" * 6


def test_render_capture_writes_pcap(spec, tmp_path):
    pk = render_capture(spec, tmp_path)
    out = tmp_path / capture_filename(spec)
    with out.open("rb") as f:
        r = dpkt.pcap.Reader(f)
        assert r.datalink() == dpkt.pcap.DLT_EN10MB
        n = sum(1 for _ in r)
    assert n == len(build_frames(spec)[0])
    assert pk == build_frames(spec)[1]


def _attrs(data):
    out, i = {}, 0
    while i < len(data):
        out[data[i]] = data[i + 2:i + data[i + 1]]
        i += data[i + 1]
    return out


def test_radius_request_attrs_and_shared_auth(spec):
    frames, pk = build_frames(spec)
    rs = [dpkt.radius.RADIUS(_udp(frames[n - 1][1])[2].data) for n in pk["pk1"]]
    assert len({r.auth for r in rs}) == 1
    a = _attrs(_udp(frames[pk["pk1"][0] - 1][1])[2].data[20:])
    assert str(ipaddress.IPv4Address(a[4])) == "10.10.100.2"
    assert a[31] == b"00-00-5E-00-53-80"
    assert a[87] == b"GigabitEthernet1/0/18"


def _eap(value):
    code, ident, length = value[0], value[1], int.from_bytes(value[2:4], "big")
    assert length == len(value)
    return code, ident, (value[4], value[5:]) if length > 4 else None


def test_access_request_is_8021x_shaped(spec):
    frames, pk = build_frames(spec)
    reqs = [_udp(frames[n - 1][1])[2].data for n in pk["pk1"]]
    assert len(set(reqs)) == 1  # retransmits are byte-identical
    a = _attrs(reqs[0][20:])
    assert a[6] == (2).to_bytes(4, "big")  # Service-Type Framed
    assert a[12] == (1485).to_bytes(4, "big")  # Framed-MTU
    assert len(a[5]) == 4 and int.from_bytes(a[5], "big") > 0  # NAS-Port
    code, ident, rest = _eap(a[79])
    assert (code, rest) == (2, (1, b"user18"))  # EAP-Response/Identity
    assert len(a[80]) == 16


@pytest.mark.parametrize("outcome,eap_code", [("accept", 3), ("reject", 4)])
def test_replies_carry_eap_result_with_matching_identifier(spec, outcome, eap_code):
    spec["capture"]["flows"][1]["params"]["outcome"] = outcome
    frames, pk = build_frames(spec)
    req = _attrs(_udp(frames[pk["pk2"][0] - 1][1])[2].data[20:])
    rep = _attrs(_udp(frames[pk["pk2"][1] - 1][1])[2].data[20:])
    code, ident, rest = _eap(rep[79])
    assert code == eap_code and rest is None
    assert ident == _eap(req[79])[1]
    assert len(rep[80]) == 16


def test_eap_fields_are_seeded_per_flow(spec):
    a = _attrs(_udp(build_frames(spec)[0][build_frames(spec)[1]["pk1"][0] - 1][1])[2].data[20:])
    spec["meta"]["id"] = "pkt-aaaaaa"
    frames, pk = build_frames(spec)
    b = _attrs(_udp(frames[pk["pk1"][0] - 1][1])[2].data[20:])
    assert a[80] != b[80]


def test_routed_replies_come_from_gateway(spec):
    frames, pk = build_frames(spec)
    gw, nas = bytes.fromhex("00005e005302"), bytes.fromhex("00005e005301")
    req_e, req_ip, req_u = _udp(frames[pk["pk2"][0] - 1][1])
    eth, ip, udp = _udp(frames[pk["pk2"][1] - 1][1])
    assert (eth.src, eth.dst) == (gw, nas)
    assert ip.ttl == 63
    assert (udp.sport, udp.dport) == (1812, req_u.sport)
    assert dpkt.radius.RADIUS(udp.data).id == dpkt.radius.RADIUS(req_u.data).id
    # DNS: pc-18 -> dns-1 via the gateway; reply is delivered by the gateway to pc-18
    q_e, q_ip, q_u = _udp(frames[pk["pk3"][0] - 1][1])
    r_e, r_ip, r_u = _udp(frames[pk["pk3"][1] - 1][1])
    assert (r_e.src, r_e.dst) == (gw, q_e.src)
    assert (r_u.sport, r_u.dport) == (53, q_u.sport)
    assert dpkt.dns.DNS(r_u.data).id == dpkt.dns.DNS(q_u.data).id
    assert r_ip.ttl == 63
    # non-via flow unaffected: ARP request is broadcast from the sender
    assert dpkt.ethernet.Ethernet(frames[pk["pk4"][0] - 1][1]).dst == b"\xff" * 6


def test_dns_ok_gratuitous_timeout(spec, tmp_path):
    fl = spec["capture"]["flows"]
    fl[2]["params"] = {"outcome": "ok", "name": "fileserver.corp.example.com", "answer": "ise-a"}
    fl[3].update(dst=fl[3]["src"], params={"outcome": "gratuitous"})
    fl.append({**fl[2], "id": "pk5", "t": "2026-10-20T14:07:00Z",
               "params": {"outcome": "timeout", "name": "x.example.org", "retries": 1}})
    frames, pk = build_frames(spec)
    dns = dpkt.dns.DNS(_udp(frames[pk["pk3"][1] - 1][1])[2].data)
    assert dns.rcode == 0
    assert str(ipaddress.IPv4Address(dns.an[0].ip)) == "10.20.0.10"
    assert len(pk["pk4"]) == 1
    arp = dpkt.ethernet.Ethernet(frames[pk["pk4"][0] - 1][1]).data
    assert arp.spa == arp.tpa
    assert len(pk["pk5"]) == 2
    render_capture(spec, tmp_path)


def test_replicate_tags_flow_vlan(spec):
    spec["capture"]["span"] = {"encapsulation": "replicate", "trunk_vlans": [1, 100]}
    next(f for f in spec["capture"]["flows"] if f["id"] == "pk3")["vlan"] = 100
    frames, pk = build_frames(spec)
    for n in pk["pk3"]:
        eth = dpkt.ethernet.Ethernet(frames[n - 1][1])
        assert eth.vlan_tags[0].id == 100
        assert isinstance(eth.data, dpkt.ip.IP)
    for n in pk["pk4"]:  # native VLAN 1: untagged
        assert frames[n - 1][1][12:14] == b"\x08\x06"


def test_replicate_unresolved_vlan_untagged(spec):
    spec["capture"]["span"] = {"encapsulation": "replicate", "trunk_vlans": [1, 100]}
    frames, pk = build_frames(spec)  # no endpoint declares a VLAN
    assert all(frames[n - 1][1][12:14] != b"\x81\x00" for nums in pk.values() for n in nums)


def _erspan_parts(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    gre = bytes(ip.data)
    return eth, ip, gre[:4], int.from_bytes(gre[4:8], "big"), gre[8:16], gre[16:]


def test_erspan_wrap(spec):
    native = build_frames(copy.deepcopy(spec))[0]
    frames, pk = build_frames(_erspan_spec(spec))
    assert len(frames) == len(native)
    seqs = []
    for (ts, buf), (nts, nbuf) in zip(frames, native):
        eth, ip, gre, seq, hdr, inner = _erspan_parts(buf)
        assert ts == nts
        assert eth.dst == bytes.fromhex("00005e005330") and eth.src == bytes.fromhex("00005e005302")
        assert ip.p == 47 and str(ipaddress.IPv4Address(ip.dst)) == "10.30.0.5" and ip.ttl == 254
        assert str(ipaddress.IPv4Address(ip.src)) == "10.10.100.2"
        assert gre == bytes.fromhex("100088be")
        assert hdr[0] >> 4 == 1 and int.from_bytes(hdr[2:4], "big") & 0x3FF == 100
        assert inner == nbuf
        seqs.append(seq)
    assert all(b == (a + 1) % 2**32 for a, b in zip(seqs, seqs[1:]))
    assert pk == build_frames(copy.deepcopy(spec))[1]


def test_erspan_no_via(spec):
    frames, _ = build_frames(_erspan_spec(spec, via=False))
    eth, ip, *_ = _erspan_parts(frames[0][1])
    assert eth.src == bytes.fromhex("00005e005301") and ip.ttl == 255


def test_erspan_deterministic(spec):
    s = _erspan_spec(spec)
    assert build_frames(s) == build_frames(copy.deepcopy(s))


def test_pk_map_counts_kept_frames_only(spec):
    frames, pk = build_frames(spec)
    assert max(n for nums in pk.values() for n in nums) <= len(frames)
    for n in pk["pk1"]:
        _, ip, udp = _udp(frames[n - 1][1])
        assert udp.dport == 1812


SSTP = bytes.fromhex("01000ccccccd")
SNAP = bytes.fromhex("aaaa0300000c010b")


def _pvst(spec, vlans):
    spec["capture"]["span"] = {"encapsulation": "replicate", "trunk_vlans": vlans}
    return spec


def _sstp_vlan(buf):
    """(802.1Q VLAN or None, PVID TLV VLAN) of an SSTP BPDU frame."""
    tag = int.from_bytes(buf[14:16], "big") & 0xFFF if buf[12:14] == b"\x81\x00" else None
    body = buf[18:] if tag is not None else buf[14:]
    assert body[:8] == SNAP
    tlv = body[8 + 36:8 + 36 + 6]
    assert tlv[:4] == bytes.fromhex("00000002")
    return tag, int.from_bytes(tlv[4:6], "big")


def test_pvst_bpdus_per_vlan(spec):
    frames, _ = build_frames(_pvst(spec, [1, 10, 30]))
    ieee = [ts for ts, b in frames if b[:6] == STP]
    sstp = [(ts, _sstp_vlan(b)) for ts, b in frames if b[:6] == SSTP]
    t0 = ieee[0]
    tick = {v for ts, v in sstp if ts == t0}
    assert tick == {(None, 1), (10, 10), (30, 30)}
    assert len(sstp) == 3 * len(ieee)


def test_pruned_vlan_bpdus_stop(spec):
    spec = _pvst(spec, [1, 10, 30])
    spec["config_diffs"] = [{"id": "cd1", "device": "DIST-SW1", "t_change": "2026-10-20T14:04:00Z",
                             "before": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10,30",
                             "after": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10", "note": None}]
    cut = parse_utc("2026-10-20T14:04:00Z").timestamp()
    v30 = [ts for ts, b in build_frames(spec)[0] if b[:6] == SSTP and _sstp_vlan(b)[1] == 30]
    assert v30 and all(ts < cut for ts in v30)
    v10 = [ts for ts, b in build_frames(spec)[0] if b[:6] == SSTP and _sstp_vlan(b)[1] == 10]
    assert any(ts >= cut for ts in v10)


def test_entity_peer_no_bpdus(spec):
    spec = _pvst(spec, [1, 10])
    spec["capture"]["peer"] = "pc-18"
    del spec["capture"]["peer_interface"]
    frames, _ = build_frames(spec)
    assert not any(b[:6] in (STP, SSTP) for _, b in frames)


TRUNK = Path(__file__).parent / "fixtures" / "trunk_pruned_capture.json"


def test_noise_arp_respects_pruned_vlan():
    spec = json.loads(TRUNK.read_text())
    spec["capture"]["noise"] = "high"
    cut = parse_utc("2026-10-21T14:03:00Z").timestamp()
    gw30 = bytes.fromhex("00005e005303")
    frames, _ = build_frames(spec)
    assert not any(ts >= cut and b[6:12] == gw30 for ts, b in frames)


def test_phase1_bytes_unchanged():
    import hashlib
    want = {"trunk_pruned_capture": "8dfa6983e33499e0514d9dd056c0d92ae7fa37a604e4e85d823229d371894614",
            "radius_capture": "a4f7c1e210b061031e47d7f5ffd03dedd785d8c33219f27388b3beed8fbbec08"}
    for name, digest in want.items():
        frames, _ = build_frames(json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text()))
        got = hashlib.sha256(b"".join(b for _, b in frames) + repr([t for t, _ in frames]).encode()).hexdigest()
        assert got == digest, name


def test_pvst_untagged_sstp_carries_peer_native(spec):
    spec = _pvst(spec, [1, 99])
    spec["config_diffs"] = [{"id": "cd1", "device": "DIST-SW1", "t_change": "2026-10-20T14:04:00Z",
                             "before": "interface GigabitEthernet1/0/1\n switchport mode trunk\n",
                             "after": "interface GigabitEthernet1/0/1\n switchport trunk native vlan 99\n",
                             "note": None}]
    cut = parse_utc("2026-10-20T14:04:00Z").timestamp()
    seen = {(ts >= cut, _sstp_vlan(b)) for ts, b in build_frames(spec)[0] if b[:6] == SSTP}
    assert seen == {(False, (None, 1)), (False, (99, 99)), (True, (None, 99)), (True, (1, 1))}


# --- phase 2 frame builders ------------------------------------------------------------------

def _add(spec, **kw):
    fl = {"id": "pk9", "t": "2026-10-20T14:07:00Z", "via": None, "label": "noise", "caused_by": None, **kw}
    spec["capture"]["flows"].append(fl)
    return fl


def _own(spec, fid="pk9"):
    frames, pk = build_frames(spec)
    return [frames[n - 1] for n in pk[fid]]


def test_stp_bpdu_frames(rep):
    _add(rep, kind="stp_bpdu", src="ACC-SW1:Gi1/0/48", dst="DIST-SW1:Gi1/0/1",
         params={"outcome": "topology_change", "count": 5})
    own = _own(rep)
    assert len(own) == 5
    t0 = parse_utc("2026-10-20T14:07:00Z").timestamp()
    assert own[0][0] == t0
    assert all(abs(ts - (t0 + 2 * i)) <= 0.005 for i, (ts, _) in enumerate(own))
    for _, b in own:
        assert b[:6] == STP and b[6:12] == bytes.fromhex("00005e005311")
        assert b[14:17] == b"\x42\x42\x03" and b[17 + 4] & 0x01  # TC bit in the flags byte
        assert b[17 + 5:17 + 7] == bytes.fromhex("8001")  # root id priority 32768 + VLAN 1


def test_cdp_frames_decode(rep):
    rep["capture"]["span"]["trunk_vlans"] = [1, 99]
    _add(rep, kind="cdp", src="DIST-SW1:Gi1/0/1", dst="ACC-SW1:Gi1/0/48",
         params={"outcome": "announce", "native_vlan": 99, "device_id": "DIST-SW1", "port_id": "GigabitEthernet1/0/1"})
    (_, b), = _own(rep)
    assert b[:6] == bytes.fromhex("01000ccccccc") and b[12:14] != b"\x81\x00"  # peer native 1: untagged
    assert b[14:22] == bytes.fromhex("aaaa0300000c2000")
    payload = b[22:14 + int.from_bytes(b[12:14], "big")]
    cdp = dpkt.cdp.CDP(payload)
    tlv = {t.type: t.data for t in map(dpkt.cdp.CDP.TLV, cdp.tlvs)}  # dpkt keeps decoded TLVs as bytes
    assert cdp.version == 2 and cdp.ttl == 180
    assert tlv[dpkt.cdp.CDP_DEVID] == b"DIST-SW1" and tlv[dpkt.cdp.CDP_NATIVE_VLAN] == (99).to_bytes(2, "big")
    assert dpkt.in_cksum(payload) == 0  # the checksum covers the payload


def test_cdp_from_peer_tagged_vlan1_when_peer_native_differs(rep):
    rep["capture"]["span"]["trunk_vlans"] = [1, 99]
    rep["config_diffs"] = [{"id": "cd1", "device": "DIST-SW1", "t_change": "2026-10-20T14:04:00Z",
                            "before": "interface GigabitEthernet1/0/1\n switchport mode trunk\n",
                            "after": "interface GigabitEthernet1/0/1\n switchport trunk native vlan 99\n",
                            "note": None}]
    _add(rep, kind="cdp", src="DIST-SW1:Gi1/0/1", dst="ACC-SW1:Gi1/0/48",
         params={"outcome": "announce", "native_vlan": 99, "device_id": "DIST-SW1", "port_id": "GigabitEthernet1/0/1"})
    (_, b), = _own(rep)
    assert dpkt.ethernet.Ethernet(b).vlan_tags[0].id == 1


def _hsrp(spec, outcome):
    _add(spec, kind="hsrp_hello", src="DIST-SW1:Vlan100", dst="ACC-SW1:Vlan100",
         params={"outcome": outcome, "group": 10, "vip": "10.10.100.254", "priority": 110, "count": 3})
    return _own(spec)


def test_hsrp_active_uses_virtual_mac(spec):
    own = _hsrp(spec, "active")
    assert len(own) == 3
    for _, b in own:
        eth = dpkt.ethernet.Ethernet(b)
        ip, udp = eth.data, eth.data.data
        assert eth.dst == bytes.fromhex("01005e000002") and eth.src == bytes.fromhex("00000c07ac0a")
        assert str(ipaddress.IPv4Address(ip.dst)) == "224.0.0.2" and ip.ttl == 1
        assert udp.sport == udp.dport == 1985
        h = dpkt.hsrp.HSRP(udp.data)
        assert (h.state, h.group, h.priority, h.hello, h.hold) == (16, 10, 110, 3, 10)
        assert h.auth == b"cisco\x00\x00\x00" and str(ipaddress.IPv4Address(h.vip)) == "10.10.100.254"


def test_hsrp_standby_uses_bia(spec):
    (_, b), *_ = _hsrp(spec, "standby")
    eth = dpkt.ethernet.Ethernet(b)
    assert eth.src == bytes.fromhex("00005e005302") and dpkt.hsrp.HSRP(eth.data.data.data).state == 8


def _dhcp(spec, outcome, **params):
    _add(spec, kind="dhcp", src="pc-18", dst="dns-1", via="DIST-SW1:Vlan100", params={"outcome": outcome, **params})
    return _own(spec)


def _dhcp_type(b):
    d = dpkt.dhcp.DHCP(dpkt.ethernet.Ethernet(b).data.data.data)
    return dict(d.opts)[dpkt.dhcp.DHCP_OPT_MSGTYPE][0], d


def test_dhcp_no_offer_retries(spec):
    own = _dhcp(spec, "no_offer")
    assert [round(ts - own[0][0], 6) for ts, _ in own] == [0.0, 4.0, 8.0, 12.0]
    for _, b in own:
        eth = dpkt.ethernet.Ethernet(b)
        assert eth.dst == b"\xff" * 6 and eth.src == bytes.fromhex("00005e005380")
        assert ipaddress.IPv4Address(eth.data.src) == ipaddress.IPv4Address("0.0.0.0")
        mtype, d = _dhcp_type(b)
        assert mtype == dpkt.dhcp.DHCPDISCOVER and d.chaddr[:6] == bytes.fromhex("00005e005380")
    assert len({_dhcp_type(b)[1].xid for _, b in own}) == 1


def test_dhcp_ack_dora_order(spec):
    own = _dhcp(spec, "ack")
    types = [_dhcp_type(b)[0] for _, b in own]
    assert types == [dpkt.dhcp.DHCPDISCOVER, dpkt.dhcp.DHCPOFFER, dpkt.dhcp.DHCPREQUEST, dpkt.dhcp.DHCPACK]
    offer = dpkt.ethernet.Ethernet(own[1][1])
    assert offer.src == bytes.fromhex("00005e005302") and offer.dst == bytes.fromhex("00005e005380")
    assert str(ipaddress.IPv4Address(dpkt.dhcp.DHCP(offer.data.data.data).yiaddr)) == "10.10.100.50"


def test_dhcp_copies_repeat_within_2ms(spec):
    own = _dhcp(spec, "no_offer", retries=0, copies=6)
    assert len(own) == 6 and len({b for _, b in own}) == 1
    assert own[-1][0] - own[0][0] <= 6 * 0.002


def test_dhcp_storm_under_cap(spec):
    from packetgen.build import MAX_CAPTURE_FRAMES
    _add(spec, kind="dhcp", src="pc-18", dst="dns-1", via="DIST-SW1:Vlan100",
         params={"outcome": "no_offer", "retries": 5, "copies": 50})
    frames, pk = build_frames(spec)
    assert len(pk["pk9"]) == 300 and len(frames) < MAX_CAPTURE_FRAMES
