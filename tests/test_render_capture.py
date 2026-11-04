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


def test_noise_medium_has_bpdus(spec):
    frames, _ = build_frames(spec)
    assert abs(sum(b[:6] == STP for _, b in frames) - 300) <= 1


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
