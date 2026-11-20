"""Capture validation (PK1-PK5) and flows in the causal graph. Mutates a copy of the radius fixture."""
import copy
import json
import sys
from pathlib import Path

from packetgen.registry import load_registry
from packetgen.validate import validate

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = json.loads((ROOT / "tests" / "fixtures" / "radius_capture.json").read_text())


def spec() -> dict:
    return copy.deepcopy(CLEAN)


def flow(s: dict, fid: str) -> dict:
    return next(f for f in s["capture"]["flows"] if f["id"] == fid)


def ev(s: dict, eid: str) -> dict:
    return next(e for e in s["events"] if e["id"] == eid)


def errors(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "error"}


def test_fixture_validates_clean():
    assert [f for f in validate(spec(), REG) if f["severity"] == "error"] == []


def test_validate_without_dpkt(monkeypatch):
    monkeypatch.setitem(sys.modules, "dpkt", None)
    assert errors(spec()) == set()


def test_pk1_not_a_link():
    s = spec()
    s["topology"]["links"] = []
    assert "PK1" in errors(s)


def test_pk1_unknown_interface():
    s = spec()
    s["capture"]["interface"] = "Gi9/9/9"
    assert "PK1" in errors(s)


def test_pk1_unknown_device():
    s = spec()
    s["capture"]["peer"] = "NOPE"
    assert "PK1" in errors(s)


def test_pk2_flow_after_end():
    s = spec()
    flow(s, "pk1")["t"] = "2026-10-20T14:09:50Z"
    assert "PK2" in errors(s)


def test_pk2_inclusive_end():
    s = spec()
    f = flow(s, "pk4")
    f.update(t="2026-10-20T14:10:00Z", src="printer-7", dst="printer-7",
             params={"outcome": "gratuitous"})
    assert "PK2" not in errors(s)


def test_pk2_start_after_end():
    s = spec()
    s["capture"]["start"] = "2026-10-20T14:11:00Z"
    assert "PK2" in errors(s)


def test_pk3_unresolvable_dst():
    s = spec()
    flow(s, "pk2")["dst"] = "nowhere"
    assert "PK3" in errors(s)


def test_pk3_client_without_mac():
    s = spec()
    flow(s, "pk1")["params"]["client"] = "old-nas"
    assert "PK3" in errors(s)


def test_pk3_unresolvable_via():
    s = spec()
    flow(s, "pk1")["via"] = "DIST-SW1:Nope"
    assert "PK3" in errors(s)


def test_pk4_bad_outcome():
    s = spec()
    flow(s, "pk1")["params"]["outcome"] = "maybe"
    assert "PK4" in errors(s)


def test_pk4_bad_dns_name():
    s = spec()
    flow(s, "pk3")["params"]["name"] = "files.corp.local"
    assert "PK4" in errors(s)


def test_pk4_gratuitous_dst_not_src():
    s = spec()
    flow(s, "pk4")["params"] = {"outcome": "gratuitous"}
    assert "PK4" in errors(s)


def test_pk4_dns_aaaa_ok():
    s = spec()
    flow(s, "pk3")["params"] = {"outcome": "ok", "name": "a.example.com", "qtype": "AAAA", "answer": "pc-18"}
    assert "PK4" in errors(s)


def test_pk5_symptom_kind_without_rule():
    s = spec()
    flow(s, "pk3").update(label="symptom", caused_by="e1")
    assert "PK5" in errors(s)


def test_pk5_no_response_outside_dead():
    s = spec()
    ev(s, "e1")["t"] = "2026-10-20T14:05:00Z"
    found = [f for f in validate(s, REG) if f["check"] == "PK5"]
    assert any("pk1" in f["message"] for f in found)
    assert "T3" in errors(s)


def test_pk5_answered_while_dead():
    s = spec()
    flow(s, "pk2")["dst"] = "ise-a"
    assert "PK5" in errors(s)


def test_pk5_alive_ends_dead_period():
    s = spec()
    s["events"].append({"id": "e6", "t": "2026-10-20T14:03:00Z", "device": "ACC-SW1",
                        "format_id": "IOS:RADIUS-4-RADIUS_ALIVE", "fields": {"ip": "10.20.0.10"},
                        "label": "noise", "caused_by": None, "signal": None})
    flow(s, "pk2")["dst"] = "ise-a"
    assert "PK5" not in errors(s)


def test_c2_flow_dangling():
    s = spec()
    flow(s, "pk1")["caused_by"] = "pk9"
    assert "C2" in errors(s)


def test_c3_noise_flow_with_parent():
    s = spec()
    flow(s, "pk3")["caused_by"] = "e1"
    assert "C3" in errors(s)


def test_t3_flow_before_cause():
    s = spec()
    flow(s, "pk1")["t"] = "2026-10-20T14:01:00Z"
    assert "T3" in errors(s)


def test_k1_accepts_pk():
    s = spec()
    assert "K1" not in errors(s)
    s["answer"]["rubric"][0]["evidence_refs"].append("pk99")
    assert "K1" in errors(s)


def test_n1_counts_flows():
    s = spec()
    s["meta"]["difficulty"]["min_noise"] = 3 + 3
    assert "N1" not in errors(s)
    s["meta"]["difficulty"]["min_noise"] = 3 + 4
    assert "N1" in errors(s)


def test_l1_capture_string():
    s = spec()
    s["answer"]["root_cause_terms"].append("user18")
    assert "L1" in errors(s)


def test_e2_interface_ip():
    s = spec()
    ev(s, "e3")["fields"]["ip"] = "10.10.100.2"
    assert "E2" not in errors(s)


def test_fixture_story_failover_follows_the_timed_out_attempts():
    """IOS radius-server deadtime 0 (not checked against gear): ise-a is tried first, then ise-b answers."""
    from datetime import timedelta

    from packetgen.timebase import parse_utc

    s = spec()
    pk1, pk2 = flow(s, "pk1"), flow(s, "pk2")
    p = pk1["params"]
    last = parse_utc(pk1["t"]) + timedelta(seconds=p["timeout_s"] * p["retries"])
    assert parse_utc(pk1["t"]) >= parse_utc(ev(s, "e1")["t"])  # T3: the symptom flow starts after the DEAD event
    assert parse_utc(pk2["t"]) >= last + timedelta(seconds=p["timeout_s"])


def test_c5_duplicate_pk_id():
    s = spec()
    flow(s, "pk2")["id"] = "pk1"
    assert "C5" in errors(s)


def test_c5_duplicate_event_id():
    s = spec()
    ev(s, "e4")["id"] = "e3"
    found = [f for f in validate(s, REG) if f["check"] == "C5"]
    assert found and "e3" in found[0]["message"] and "events" in found[0]["message"]


def test_pk4_nas_port_too_long_does_not_crash_build():
    s = spec()
    flow(s, "pk1")["params"]["nas_port"] = "G" * 300
    assert "PK4" in errors(s)


def test_pk3_unparsable_mac():
    s = spec()
    s["topology"]["entities"]["printer-7"]["mac"] = "zz:zz:5e:00:53:81"
    assert "PK3" in errors(s)


def test_pk3_ipv6_endpoint():
    s = spec()
    s["topology"]["entities"]["ise-a"]["ip"] = "2001:db8::1"
    assert "PK3" in errors(s)


def test_pk3_unparsable_interface_mac_used_by_noise():
    s = spec()
    s["topology"]["devices"][1]["interfaces"][1]["mac"] = "nonsense"
    assert "PK3" in errors(s)


# --- capture methods: PK1 entity peer, PK5 ARP, PK8, PK9, K4, L1 reason -------------------------

PRUNE = {"id": "cd1", "device": "DIST-SW1", "t_change": "2026-10-20T14:04:00Z",
         "before": "interface Gi1/0/1\n switchport trunk allowed vlan 1,10,30",
         "after": "interface Gi1/0/1\n switchport trunk allowed vlan 1,10", "note": None}


def arp_symptom(t: str = "2026-10-20T14:06:20Z", pruned: bool = True) -> dict:
    """pk4 (unanswered ARP) as a VLAN-30 symptom on a replicate SPAN, with DIST-SW1's trunk edit."""
    s = spec()
    s["capture"]["span"] = {"encapsulation": "replicate", "trunk_vlans": [1, 10, 30]}
    fl = flow(s, "pk4")
    fl.update(label="symptom", caused_by="e1", vlan=30, t=t)
    if pruned:
        s["config_diffs"] = [dict(PRUNE)]
    return s


def test_pk1_entity_peer_on_port():
    s = spec()
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "interface": "Gi1/0/48"}
    s["capture"]["peer"] = "pc-18"
    del s["capture"]["peer_interface"]
    assert "PK1" not in errors(s)
    s["topology"]["entities"]["pc-18"]["attached"]["interface"] = "Gi1/0/7"
    assert "PK1" in errors(s)


def test_pk1_device_peer_needs_interface():
    s = spec()
    del s["capture"]["peer_interface"]
    assert "PK1" in errors(s)


def test_pk5_arp_pruned_ok():
    assert {"PK5", "PK8", "PK9"} & errors(arp_symptom()) == set()


def test_pk5_arp_symptom_needs_no_reply():
    s = arp_symptom()
    flow(s, "pk4")["params"]["outcome"] = "reply"
    s["topology"]["entities"]["old-nas"]["mac"] = "00:00:5e:00:53:99"
    assert "PK5" in errors(s)


def test_pk5_arp_vlan_not_pruned():
    assert "PK5" in errors(arp_symptom(pruned=False))
    s = arp_symptom()
    s["config_diffs"][0]["after"] = "interface Gi1/0/1\n switchport trunk allowed vlan 1,10,30"
    assert "PK5" in errors(s)


def test_pk5_arp_at_t_change_boundary():
    assert "PK5" not in errors(arp_symptom(t="2026-10-20T14:04:00Z"))
    assert "PK5" in errors(arp_symptom(t="2026-10-20T14:03:59Z"))


def test_pk8_invisible_symptom(monkeypatch):
    from packetgen import capture
    monkeypatch.setattr(capture, "flow_class", lambda s, fl: "l2_control")
    assert "PK8" in errors(spec())


def test_pk9_reason_names_device():
    s = spec()
    s["capture"]["reason"] = "Local SPAN on the access uplink so both sides show up."
    assert "PK9" in errors(s)


def test_pk9_vlan_not_on_trunk():
    s = arp_symptom()
    s["capture"]["span"]["trunk_vlans"] = [1, 10]
    assert "PK9" in errors(s)


def _erspan(s: dict) -> dict:
    s["topology"]["entities"]["analyzer-1"] = {"ip": "10.30.0.5", "mac": "00:00:5e:00:53:30"}
    cap = s["capture"]
    cap["method"] = "erspan"
    del cap["span"]
    cap["erspan"] = {"origin_ip": "10.10.100.2", "analyzer": "analyzer-1", "session": 1, "erspan_id": 100,
                     "via": "DIST-SW1:Vlan100"}
    return s


def test_erspan_spec_validates_clean():
    assert errors(_erspan(spec())) == set()


def test_pk9_erspan_analyzer_missing():
    s = _erspan(spec())
    del s["topology"]["entities"]["analyzer-1"]["mac"]
    assert "PK9" in errors(s)
    s["capture"]["erspan"]["analyzer"] = "nope"
    assert "PK9" in errors(s)


def test_pk9_erspan_origin_ip_not_on_device():
    s = _erspan(spec())
    s["capture"]["erspan"]["origin_ip"] = "10.10.100.1"  # DIST-SW1's SVI
    assert "PK9" in errors(s)


def test_pk9_erspan_via_unresolved():
    s = _erspan(spec())
    s["capture"]["erspan"]["via"] = "DIST-SW1:Gi9/9"
    assert "PK9" in errors(s)


def test_k4_no_capture_rubric():
    s = spec()
    for item in s["answer"]["rubric"]:
        item["evidence_refs"] = [r for r in item["evidence_refs"] if r != "pk1"]
    assert "K4" in errors(s)


def test_l1_reason_leak():
    s = spec()
    s["capture"]["reason"] = "Local SPAN on ACC-SW1 Gi1/0/48 to watch the RADIUS traffic."
    assert "L1" in errors(s)


def test_pk5_arp_after_restore_fails():
    s = json.loads((ROOT / "tests" / "fixtures" / "trunk_pruned_capture.json").read_text())
    s["config_diffs"].append({"id": "cd2", "device": "DIST-SW1", "t_change": "2026-10-21T14:04:30Z",
                              "before": "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan 1,10\n",
                              "after": "interface GigabitEthernet1/0/1\n switchport mode trunk\n", "note": None})
    assert "PK5" in errors(s)


def test_pk5_arp_edit_on_other_port_fails():
    s = json.loads((ROOT / "tests" / "fixtures" / "trunk_pruned_capture.json").read_text())
    for side in ("before", "after"):
        s["config_diffs"][0][side] = s["config_diffs"][0][side].replace("GigabitEthernet1/0/1\n", "GigabitEthernet1/0/2\n")
    assert "PK5" in errors(s)


# --- phase 2 kinds: PK3/PK4/PK8 ---------------------------------------------------------------

def add_flow(s: dict, **kw) -> dict:
    fl = {"id": "pk9", "t": "2026-10-20T14:07:00Z", "via": None, "label": "noise", "caused_by": None, **kw}
    s["capture"]["flows"].append(fl)
    return fl


def test_pk3_dhcp_needs_relay():
    s = spec()
    add_flow(s, kind="dhcp", src="pc-18", dst="dns-1", params={"outcome": "no_offer"})
    assert "PK3" in errors(s)
    s["capture"]["flows"][-1]["via"] = "DIST-SW1:Vlan100"
    assert "PK3" not in errors(s)


def test_pk3_dhcp_ack_needs_client_ip():
    s = spec()
    s["topology"]["entities"]["pc-new"] = {"mac": "00:00:5e:00:53:82"}
    add_flow(s, kind="dhcp", src="pc-new", dst="dns-1", via="DIST-SW1:Vlan100", params={"outcome": "ack"})
    assert "PK3" in errors(s)


def test_pk4_cdp_vlan_must_be_1():
    s = spec()
    fl = add_flow(s, kind="cdp", src="DIST-SW1:Gi1/0/1", dst="ACC-SW1:Gi1/0/48",
                  params={"outcome": "announce", "native_vlan": 1, "device_id": "DIST-SW1", "port_id": "Gi1/0/1"})
    assert "PK4" not in errors(s)
    fl["vlan"] = 10
    assert "PK4" in errors(s)


def test_pk8_bpdu_symptom_on_native_span():
    s = spec()
    add_flow(s, kind="stp_bpdu", src="DIST-SW1:Gi1/0/1", dst="ACC-SW1:Gi1/0/48", params={"outcome": "bpdu"},
             label="symptom", caused_by="e1")
    assert "PK8" in errors(s)
