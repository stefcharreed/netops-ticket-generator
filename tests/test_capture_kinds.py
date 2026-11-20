"""Flow-kind catalog and endpoint resolution (pure; no dpkt)."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from packetgen import capture, capture_kinds

ROOT = Path(__file__).parents[1]
SPEC = json.loads((ROOT / "tests" / "fixtures" / "radius_capture.json").read_text())
PK1 = SPEC["capture"]["flows"][0]


def test_span_radius_no_response():
    assert capture_kinds.span_s(PK1) == 15.0


def test_span_defaults():
    flow = {"kind": "radius_request", "params": {"outcome": "no_response"}}
    assert capture_kinds.span_s(flow) == 15.0


def test_span_answered_and_other_kinds():
    k = capture_kinds.span_s
    assert k({"kind": "radius_request", "params": {"outcome": "accept"}}) == 0.05
    assert k({"kind": "arp", "params": {"outcome": "no_reply"}}) == 2.0
    assert k({"kind": "arp", "params": {"outcome": "no_reply", "retries": 3}}) == 3.0
    assert k({"kind": "arp", "params": {"outcome": "reply"}}) == 0.01
    assert k({"kind": "arp", "params": {"outcome": "gratuitous"}}) == 0.0
    assert k({"kind": "dns_query", "params": {"outcome": "timeout"}}) == 2.0
    assert k({"kind": "dns_query", "params": {"outcome": "nxdomain"}}) == 0.05


def test_expected_filter_pk1():
    assert capture_kinds.expected_filter(PK1) == "radius.code == 1 && !radius.rspframe"


def test_every_kind_schema_valid():
    for kind in capture_kinds.KINDS.values():
        Draft202012Validator.check_schema(kind["params"])
        assert kind["params"]["additionalProperties"] is False


def test_every_outcome_has_a_filter():
    for kind in capture_kinds.KINDS.values():
        assert set(kind["params"]["properties"]["outcome"]["enum"]) == set(kind["filters"])


def test_resolve_entity():
    assert capture.resolve_endpoint(SPEC, "ise-a") == {"mac": "00:00:5e:00:53:20", "ip": "10.20.0.10", "vlan": None}
    assert capture.resolve_endpoint(SPEC, "old-nas") == {"mac": None, "ip": "10.10.100.99", "vlan": None}


def test_resolve_host_if():
    r = capture.resolve_endpoint(SPEC, "ACC-SW1:Vlan100")
    assert r == {"mac": "00:00:5e:00:53:01", "ip": "10.10.100.2", "vlan": None}
    assert capture.resolve_endpoint(SPEC, "ACC-SW1:Gi1/0/48") == {"mac": "00:00:5e:00:53:11", "ip": None, "vlan": None}


def test_resolve_ambiguous_device_none():
    assert capture.resolve_endpoint(SPEC, "ACC-SW1") is None


def test_resolve_single_interface_device():
    s = copy.deepcopy(SPEC)
    s["topology"]["devices"][0]["interfaces"] = [
        {"name": "Vlan100", "ip": "10.10.100.2", "mac": "00:00:5e:00:53:01"}]
    r = capture.resolve_endpoint(s, "ACC-SW1")
    assert r is not None and r["ip"] == "10.10.100.2"


def test_resolve_entity_wins_over_device():
    s = copy.deepcopy(SPEC)
    s["topology"]["entities"]["ACC-SW1"] = {"ip": "192.0.2.1"}
    assert capture.resolve_endpoint(s, "ACC-SW1") == {"mac": None, "ip": "192.0.2.1", "vlan": None}


def test_resolve_unknown_none():
    assert capture.resolve_endpoint(SPEC, "nope") is None
    assert capture.resolve_endpoint(SPEC, "ACC-SW1:Gi9/9") is None


def test_capture_filename():
    assert capture.capture_filename(SPEC) == "capture_ACC-SW1_Gi1-0-48.pcap"


def test_capture_filename_hostile():
    s = copy.deepcopy(SPEC)
    s["capture"]["device"] = "..\\x"
    s["capture"]["interface"] = "Gi1/0/1\\.."
    name = capture.capture_filename(s)
    assert "/" not in name and "\\" not in name
    assert Path(name).name == name


def _errs(kind, params):
    return list(Draft202012Validator(capture_kinds.KINDS[kind]["params"]).iter_errors(params))


_RAD = {"outcome": "accept", "username": "bob", "client": "pc-18", "nas_port": "Gi1/0/1"}
_DNS = {"outcome": "nxdomain", "name": "a.example.com"}


@pytest.mark.parametrize("kind,params,ok", [
    ("radius_request", _RAD, True),
    ("arp", {"outcome": "reply"}, True),
    ("dns_query", _DNS, True),
    ("dns_query", {"outcome": "ok", "name": "a.test", "answer": "dns-1"}, True),
    ("dns_query", {"outcome": "ok", "name": "a.test"}, False),
    ("radius_request", {**_RAD, "username": "Bob"}, False),
    ("radius_request", {**_RAD, "username": "1bob"}, False),
    ("radius_request", {**_RAD, "username": "a" * 33}, False),
    ("radius_request", {**_RAD, "username": "bob\n"}, False),
    ("dns_query", {**_DNS, "name": "a.corp.local"}, False),
    ("dns_query", {**_DNS, "name": "a.test\n"}, False),
    ("dns_query", {**_DNS, "name": "xexample.com"}, False),
    ("radius_request", {**_RAD, "retries": 11}, False),
    ("radius_request", {**_RAD, "timeout_s": 0}, False),
    ("arp", {"outcome": "reply", "retries": 6}, False),
    ("arp", {"outcome": "reply", "bogus": 1}, False),
])
def test_param_schema(kind, params, ok):
    assert (not _errs(kind, params)) is ok


@pytest.mark.parametrize("text,want", [
    ("00:00:5e:00:53:01", "00005e005301"),
    ("00-00-5E-00-53-01", "00005e005301"),
    ("0000.5e00.5301", "00005e005301"),
    ("00:00:5e:00:53", None),
    ("zz:zz:5e:00:53:01", None),
    ("0000.5e00.53011", None),
    ("00:00:5e:00:53:01\n", None),
    ("", None),
])
def test_parse_mac(text, want):
    assert capture.parse_mac(text) == (bytes.fromhex(want) if want else None)


@pytest.mark.parametrize("nas_port,ok", [
    ("Gi1/0/1", True), ("G" * 64, True), ("G" * 65, False), ("Gi1\n", False), ("Gi1\x00", False), ("Gi\u00e91", False),
])
def test_nas_port_schema(nas_port, ok):
    assert (not _errs("radius_request", {**_RAD, "nas_port": nas_port})) is ok


def test_resolve_vlan_from_attached_and_interface():
    s = copy.deepcopy(SPEC)
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "interface": "Gi1/0/18", "vlan": 100}
    s["topology"]["devices"][0]["interfaces"][0]["vlan"] = 100
    assert capture.resolve_endpoint(s, "pc-18")["vlan"] == 100
    assert capture.resolve_endpoint(s, "ACC-SW1:Vlan100")["vlan"] == 100


@pytest.mark.parametrize("text,want", [
    ("interface Gi1/0/1\n switchport trunk allowed vlan 10,20,40\n", {10, 20, 40}),
    (" switchport trunk allowed vlan 10-12,30", {10, 11, 12, 30}),
    (" switchport trunk allowed vlan add 30", None),
    (" switchport trunk allowed vlan remove 30", None),
    (" switchport trunk allowed vlan all", None),
    (" switchport trunk allowed vlan none", None),
    ("interface Gi1/0/1\n switchport mode trunk\n", None),
    (" switchport trunk allowed vlan 1,10\n switchport trunk allowed vlan 1,30\n", {1, 30}),
])
def test_parse_allowed_forms(text, want):
    assert capture.parse_allowed_vlans(text) == want


def test_peer_allowed_vlans_time():
    from packetgen.timebase import parse_utc
    s = copy.deepcopy(SPEC)
    s["config_diffs"] = [{"id": "cd1", "device": "DIST-SW1", "t_change": "2026-10-20T14:04:00Z",
                          "before": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10,30",
                          "after": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10", "note": None}]
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-20T14:03:59Z")) is None
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-20T14:04:00Z")) == {1, 10}
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-20T14:05:00Z")) == {1, 10}
    s["config_diffs"][0]["device"] = "ACC-SW1"  # not the peer
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-20T14:05:00Z")) is None


def _trunk() -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / "trunk_pruned_capture.json").read_text())


def test_peer_allowed_vlans_restore_wins():
    from packetgen.timebase import parse_utc
    s = _trunk()
    s["config_diffs"].append({"id": "cd2", "device": "DIST-SW1", "t_change": "2026-10-21T14:04:30Z",
                              "before": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10\n",
                              "after": "interface GigabitEthernet1/0/1\n switchport mode trunk\n", "note": None})
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-21T14:04:00Z")) == {1, 10}
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-21T14:05:00Z")) is None  # no line = all allowed


def test_peer_allowed_vlans_unreadable_newest_is_none():
    from packetgen.timebase import parse_utc
    s = _trunk()
    s["config_diffs"].append({"id": "cd2", "device": "DIST-SW1", "t_change": "2026-10-21T14:04:30Z",
                              "before": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10\n",
                              "after": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan add 30\n",
                              "note": None})
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-21T14:05:00Z")) is None


def test_peer_allowed_vlans_other_interface_ignored():
    from packetgen.timebase import parse_utc
    s = _trunk()
    for side in ("before", "after"):
        s["config_diffs"][0][side] = s["config_diffs"][0][side].replace("GigabitEthernet1/0/1\n", "GigabitEthernet1/0/2\n")
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-21T14:05:00Z")) is None


def test_peer_allowed_vlans_picks_the_monitored_stanza():
    from packetgen.timebase import parse_utc
    s = _trunk()
    s["config_diffs"][0]["after"] = ("interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10\n"
                                     "interface GigabitEthernet1/0/2\n switchport trunk allowed vlan 1,10,30\n")
    assert capture.peer_allowed_vlans(s, parse_utc("2026-10-21T14:05:00Z")) == {1, 10}


def test_span_new_kinds():
    stp = {"kind": "stp_bpdu", "params": {"outcome": "bpdu"}}
    assert capture_kinds.span_s(stp) == 18.0
    assert capture_kinds.span_s({"kind": "cdp", "params": {"outcome": "announce", "count": 3, "interval_s": 60}}) == 120.0
    assert capture_kinds.span_s({"kind": "hsrp_hello", "params": {"outcome": "active"}}) == 12.0
    assert capture_kinds.span_s({"kind": "dhcp", "params": {"outcome": "no_offer"}}) == 12.01
    assert capture_kinds.span_s({"kind": "dhcp", "params": {"outcome": "ack"}}) == 0.1


NATIVE99 = {"id": "cd2", "device": "DIST-SW1", "t_change": "2026-10-21T14:04:00Z",
            "before": "interface GigabitEthernet1/0/1\n switchport mode trunk\n",
            "after": "interface GigabitEthernet1/0/1\n switchport mode trunk\n switchport trunk native vlan 99\n",
            "note": None}


def test_peer_native_vlan_time():
    from packetgen.timebase import parse_utc
    s = _trunk()
    s["config_diffs"].append(dict(NATIVE99))
    assert capture.peer_native_vlan(s, parse_utc("2026-10-21T14:03:59Z")) is None
    assert capture.peer_native_vlan(s, parse_utc("2026-10-21T14:05:00Z")) == 99
    s["config_diffs"].append({**NATIVE99, "id": "cd3", "t_change": "2026-10-21T14:06:00Z",
                              "before": NATIVE99["after"], "after": NATIVE99["before"]})
    assert capture.peer_native_vlan(s, parse_utc("2026-10-21T14:07:00Z")) == 1  # line removed: default 1
