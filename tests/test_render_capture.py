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


def test_noise_medium_has_bpdus(spec):
    times, _ = _bpdu_times(spec)
    assert abs(len(times) - 300) <= 1  # 600 s at 2 s, less the seeded phase offset


def test_bpdu_phase_and_jitter(spec):
    times, _ = _bpdu_times(spec)
    lo = parse_utc(spec["capture"]["start"]).timestamp()
    assert 0.0 <= times[0] - lo < 2.01
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert all(1.989 <= g <= 2.011 for g in gaps)  # 2 s +- 2 x 5 ms
    assert len({round(g, 4) for g in gaps}) > 50  # jittered, not a metronome
    spec2 = copy.deepcopy(spec)
    spec2["meta"]["id"] = "pkt-aaaaaa"
    assert (_bpdu_times(spec2)[0][0] - lo) != (times[0] - lo)  # phase is seeded per packet id


def test_bpdu_bridge_priority_includes_vlan1_ext(spec):
    _, frames = _bpdu_times(spec)
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


def test_noise_low_has_no_bpdus(spec):
    spec["capture"]["noise"] = "low"
    frames, _ = build_frames(spec)
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
