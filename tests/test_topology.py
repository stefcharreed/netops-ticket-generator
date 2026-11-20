"""Topology helpers behind the network docs: link ends, icon kinds, doc rows, overrides."""
import copy
import json
from pathlib import Path

from packetgen.capture import check_capture
from packetgen.topology import KINDS, device_kind, doc_rows, entity_kind, link_ends, mac_rows, overrides

ROOT = Path(__file__).parents[1]
STP = json.loads((ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json").read_text())
RADIUS = json.loads((ROOT / "tests" / "fixtures" / "radius_capture.json").read_text())


def test_link_ends_reads_bare_and_host_if_forms():
    assert link_ends(RADIUS) == [("ACC-SW1", None, "DIST-SW1", None)]
    assert link_ends(STP)[0] == ("ACC-SW1", "GigabitEthernet1/0/49", "DIST-SW1", "GigabitEthernet1/0/1")


def test_capture_pair_check_accepts_host_if_links():
    s = copy.deepcopy(RADIUS)
    s["topology"]["links"] = [["ACC-SW1:Gi1/0/48", "DIST-SW1:Gi1/0/1"]]
    assert not [f for f in check_capture(s) if f["check"] == "PK1"]


def test_device_kinds_from_role_and_override():
    roles = {"access-switch": "switch", "distribution-switch": "l3switch", "core-switch": "l3switch",
             "edge-router": "router", "asa-firewall": "firewall", "wlc": "wlc", "dhcp-server": "server"}
    for role, kind in roles.items():
        assert device_kind({"role": role}) == kind, role
    assert device_kind({"role": "access-switch", "icon": "router"}) == "router"
    assert device_kind({"role": "mystery-box"}) == "host"


def test_entity_kinds_from_name_and_override():
    names = {"ise-a": "aaa", "dns-1": "server", "pc-18": "pc", "printer-7": "printer", "old-nas": "server",
             "ntp-server": "server", "client-a": "pc", "voip-phone-3": "phone", "isp": "cloud", "thing": "host"}
    for name, kind in names.items():
        assert entity_kind(name, {}) == kind, name
    assert entity_kind("pc-18", {"kind": "printer"}) == "printer"
    assert set(names.values()) <= set(KINDS)


def test_doc_row_ids_are_stable_and_safe():
    s = copy.deepcopy(RADIUS)
    ids = [r["id"] for r in doc_rows(s)]
    assert "doc:ACC-SW1-mgmt" in ids and "doc:ACC-SW1-Vlan100" in ids and "doc:ise-a" in ids
    s["topology"]["devices"][0]["interfaces"].append({"name": "Gi1/0/48", "mac": "00:00:5e:00:53:31", "vlan": 100})
    assert "doc:ACC-SW1-Gi1-0-48" in [r["id"] for r in doc_rows(s)]
    assert all(r["id"].startswith("doc:") and " " not in r["id"] for r in doc_rows(s))


def test_documented_override_shows_in_rows_and_overrides():
    s = copy.deepcopy(RADIUS)
    s["topology"]["devices"][0]["documented"] = {"mgmt_ip": "10.0.0.12"}
    row = next(r for r in doc_rows(s) if r["id"] == "doc:ACC-SW1-mgmt")
    assert row["ip"] == "10.0.0.12" and row["documented"] is True
    assert overrides(s) == [("doc:ACC-SW1-mgmt", "ip", "10.0.0.12", "10.0.0.11")]
    assert overrides(RADIUS) == []


def test_mac_rows_need_mac_and_attachment():
    s = copy.deepcopy(RADIUS)
    assert mac_rows(s) == []
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "interface": "Gi1/0/5", "vlan": 100}
    s["topology"]["entities"]["pc-18"]["documented"] = {"mac": "00:00:5e:00:53:99"}
    rows = mac_rows(s)
    assert rows == [{"id": "doc:mac-pc-18", "mac": "00:00:5e:00:53:99", "ip": "10.10.100.50", "switch": "ACC-SW1",
                     "port": "Gi1/0/5", "vlan": 100, "documented": True}]
    assert ("doc:mac-pc-18", "mac", "00:00:5e:00:53:99", "0000.5e00.5380") in overrides(s)
