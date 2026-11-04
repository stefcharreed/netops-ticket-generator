"""Flow-kind catalog and endpoint resolution (pure; no dpkt)."""
import copy
import json
from pathlib import Path

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
    assert capture.resolve_endpoint(SPEC, "ise-a") == {"mac": "00:00:5e:00:53:20", "ip": "10.20.0.10"}
    assert capture.resolve_endpoint(SPEC, "old-nas") == {"mac": None, "ip": "10.10.100.99"}


def test_resolve_host_if():
    r = capture.resolve_endpoint(SPEC, "ACC-SW1:Vlan100")
    assert r == {"mac": "00:00:5e:00:53:01", "ip": "10.10.100.2"}
    assert capture.resolve_endpoint(SPEC, "ACC-SW1:Gi1/0/48") == {"mac": "00:00:5e:00:53:11", "ip": None}


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
    assert capture.resolve_endpoint(s, "ACC-SW1") == {"mac": None, "ip": "192.0.2.1"}


def test_resolve_unknown_none():
    assert capture.resolve_endpoint(SPEC, "nope") is None
    assert capture.resolve_endpoint(SPEC, "ACC-SW1:Gi9/9") is None


def test_capture_filename():
    assert capture.capture_filename(SPEC) == "capture_ACC-SW1_Gi1-0-48.pcap"
