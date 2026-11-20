"""Per-method view rules (pure; no dpkt)."""
import copy
import json
from pathlib import Path

import pytest

from packetgen import capture_views as cv

ROOT = Path(__file__).parents[1]
CLEAN = json.loads((ROOT / "tests" / "fixtures" / "radius_capture.json").read_text())
ERSPAN = {"origin_ip": "10.10.100.2", "analyzer": "analyzer-1", "session": 1, "erspan_id": 100}


def spec(method: str = "native") -> dict:
    s = copy.deepcopy(CLEAN)
    cap = s["capture"]
    if method == "erspan":
        cap["method"] = "erspan"
        del cap["span"]
        cap["erspan"] = dict(ERSPAN)
    else:
        cap["span"] = {"encapsulation": method}
        if method == "replicate":
            cap["span"]["trunk_vlans"] = [1, 100]
    return s


def flow(s: dict, fid: str) -> dict:
    return next(f for f in s["capture"]["flows"] if f["id"] == fid)


def test_flow_class_device_sourced_is_control_plane():
    s = spec()
    assert cv.flow_class(s, flow(s, "pk1")) == "control_plane"  # src ACC-SW1:Vlan100


def test_flow_class_host_is_data():
    s = spec()
    assert cv.flow_class(s, flow(s, "pk3")) == "data"  # pc-18 -> dns-1


def test_flow_class_link_local_multicast_is_control_plane():
    s = spec()
    s["topology"]["entities"]["allspf"] = {"ip": "224.0.0.5"}
    fl = flow(s, "pk3")
    fl["dst"] = "allspf"
    assert cv.flow_class(s, fl) == "control_plane"


def test_frame_class():
    assert cv.frame_class(bytes.fromhex("0180c2000000")) == "l2_control"
    assert cv.frame_class(bytes.fromhex("01000ccccccd")) == "l2_control"
    assert cv.frame_class(b"\xff" * 6) is None


@pytest.mark.parametrize("method,fclass,kept", [
    ("native", "data", True), ("native", "control_plane", True), ("native", "l2_control", False),
    ("replicate", "data", True), ("replicate", "control_plane", True), ("replicate", "l2_control", True),
    ("erspan", "data", True), ("erspan", "control_plane", True), ("erspan", "l2_control", False),
])
def test_keeps(method, fclass, kept):
    assert cv.keeps(spec(method)["capture"], fclass) is kept


def test_flow_vlan_explicit_wins():
    s = spec("replicate")
    fl = flow(s, "pk3")
    fl["vlan"] = 30
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "vlan": 100}
    assert cv.flow_vlan(s, fl) == 30


def test_flow_vlan_from_src_attached():
    s = spec("replicate")
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "vlan": 100}
    assert cv.flow_vlan(s, flow(s, "pk3")) == 100


def test_flow_vlan_native_fallback():
    s = spec("replicate")
    s["capture"]["span"]["native_vlan"] = 99
    assert cv.flow_vlan(s, flow(s, "pk3")) == 99
    assert cv.flow_vlan(spec("erspan"), flow(spec("erspan"), "pk3")) == 1


def test_tagged():
    cap = spec("replicate")["capture"]
    assert cv.tagged(cap, 1) is False
    assert cv.tagged(cap, 30) is True
    assert cv.tagged(spec("native")["capture"], 30) is False


def test_filter_suffix():
    s = spec("replicate")
    fl = flow(s, "pk3")
    assert cv.filter_suffix(s, fl) == ""  # native VLAN 1: untagged
    fl["vlan"] = 100
    assert cv.filter_suffix(s, fl) == " && vlan"
    e = spec("erspan")
    assert cv.filter_suffix(e, flow(e, "pk1")) == " && erspan"


def test_method_label():
    assert cv.method_label(spec("native")["capture"]) == "Local SPAN"
    assert cv.method_label(spec("replicate")["capture"]) == "Local SPAN (encapsulation replicate)"
    assert cv.method_label(spec("erspan")["capture"]) == "ERSPAN to analyzer-1"


def test_flow_class_l2_kinds():
    s = spec()
    fl = dict(flow(s, "pk1"), kind="stp_bpdu", params={"outcome": "bpdu"})  # src is the capture device
    assert cv.flow_class(s, fl) == "l2_control"
    fl["kind"] = "cdp"
    assert cv.flow_class(s, fl) == "l2_control"
    fl = dict(flow(s, "pk3"), kind="hsrp_hello")  # pc-18 -> dns-1, but hellos go to 224.0.0.2
    assert cv.flow_class(s, fl) == "control_plane"


def test_sender_native_peer_vs_near():
    s = json.loads((ROOT / "tests" / "fixtures" / "trunk_pruned_capture.json").read_text())
    s["config_diffs"].append({"id": "cd2", "device": "DIST-SW1", "t_change": "2026-10-21T14:04:00Z",
                              "before": "interface GigabitEthernet1/0/1\n",
                              "after": "interface GigabitEthernet1/0/1\n switchport trunk native vlan 99\n",
                              "note": None})
    fl = {"src": "DIST-SW1:Vlan10", "t": "2026-10-21T14:05:00Z"}
    assert cv.sender_native(s, fl) == 99
    assert cv.sender_native(s, {**fl, "t": "2026-10-21T14:03:00Z"}) == 1
    assert cv.sender_native(s, {**fl, "src": "pc-31"}) == 1
    cap = s["capture"]
    assert cv.tagged(cap, 1, native=99) is True and cv.tagged(cap, 99, native=99) is False
