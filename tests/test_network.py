"""Network docs: icon lookup, the pure layout, and NETWORK.md + topology.png."""
import copy
import json
from pathlib import Path

import pytest

from packetgen.icons import CISCO_FILES, icon_report, icon_source, load_icon
from packetgen.render.network import layout, render_network, short_if
from packetgen.topology import KINDS

ROOT = Path(__file__).parents[1]
STP = json.loads((ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json").read_text())
RADIUS = json.loads((ROOT / "tests" / "fixtures" / "radius_capture.json").read_text())


@pytest.fixture
def no_icons(tmp_path, monkeypatch):
    d = tmp_path / "icons"
    d.mkdir()
    monkeypatch.setenv("PACKETGEN_ICONS", str(d))   # tests never use real Cisco files
    return d


def nodes(spec):
    return {n["id"]: n for n in layout(spec)["nodes"]}


def test_short_interface_names():
    assert short_if("GigabitEthernet1/0/49") == "Gi1/0/49"
    assert short_if("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert short_if("Port-channel1") == "Po1"
    assert short_if("Vlan100") == "Vlan100"
    assert short_if(None) == ""


def test_tiers_follow_the_hierarchy():
    n = nodes(STP)
    assert n["CORE-SW1"]["y"] > n["DIST-SW1"]["y"] or n["CORE-SW1"]["tier"] == n["DIST-SW1"]["tier"]
    assert n["DIST-SW1"]["y"] > n["ACC-SW1"]["y"]
    assert n["ACC-SW1"]["y"] > n["DHCP01"]["y"]


def test_attached_hosts_sit_under_their_switch_and_others_in_the_side_row():
    s = copy.deepcopy(STP)
    s["topology"]["entities"]["client-a"]["attached"] = {"device": "ACC-SW2", "interface": "Gi1/0/48", "vlan": 20}
    n = nodes(s)
    assert n["client-a"]["y"] < n["ACC-SW2"]["y"]
    assert abs(n["client-a"]["x"] - n["ACC-SW2"]["x"]) < abs(n["client-a"]["x"] - n["ACC-SW1"]["x"]) + 1e-9
    side = [n[k] for k in ("ntp-server", "dhcp-relay")]
    assert all(v["tier"] == "side" for v in side)
    edges = layout(s)["edges"]
    assert {"a": "ACC-SW2", "b": "client-a", "a_label": "Gi1/0/48", "b_label": "", "rad": 0.0} in edges


def test_positions_unique_with_unlinked_triangle_and_duplicate_links():
    s = copy.deepcopy(STP)
    s["topology"]["links"] += [["ACC-SW1", "ACC-SW2"], ["ACC-SW1:Gi1/0/50", "DIST-SW1:Gi1/0/3"]]
    lay = layout(s)
    pos = [(round(n["x"], 3), round(n["y"], 3)) for n in lay["nodes"]]
    assert len(pos) == len(set(pos))
    rads = [e["rad"] for e in lay["edges"] if {e["a"], e["b"]} == {"ACC-SW1", "DIST-SW1"}]
    assert len(rads) == 2 and rads[0] != rads[1]


def test_labels_show_documented_values_without_marking_them():
    s = copy.deepcopy(STP)
    s["topology"]["entities"]["dhcp-relay"]["documented"] = {"ip": "10.20.20.9"}
    lab = nodes(s)["dhcp-relay"]["label"]
    assert "10.20.20.9" in lab and "10.20.20.1" not in lab
    assert set(nodes(s)["dhcp-relay"]) == set(nodes(STP)["dhcp-relay"])   # no "documented" flag leaks out


def test_docs_never_depend_on_events_or_answer(tmp_path, no_icons):
    a, b = copy.deepcopy(RADIUS), copy.deepcopy(RADIUS)
    b["events"] = b["events"][:1]
    b["answer"]["fix"] = "something else entirely"
    b["telemetry"] = []
    assert layout(a) == layout(b)
    render_network(a, tmp_path / "a", no_icons)
    render_network(b, tmp_path / "b", no_icons)
    assert (tmp_path / "a" / "NETWORK.md").read_text() == (tmp_path / "b" / "NETWORK.md").read_text()


def test_network_md_header_tables_and_manifest(tmp_path, no_icons):
    s = copy.deepcopy(RADIUS)
    man = render_network(s, tmp_path, no_icons)
    text = (tmp_path / "NETWORK.md").read_text()
    assert text.splitlines()[0].startswith("# Network documentation")
    assert "may be out of date" in text.splitlines()[2].lower()
    assert "![Documented topology](topology.png)" in text
    assert "| ACC-SW1-mgmt |" in text and "ACC-SW1 ↔ DIST-SW1" in text
    assert "## Documented MAC table" not in text
    assert "doc:ACC-SW1-mgmt" in man["NETWORK.md"] and man["topology.png"] == []
    assert (tmp_path / "topology.png").stat().st_size > 1000


def test_mac_table_only_with_flag(tmp_path, no_icons):
    s = copy.deepcopy(RADIUS)
    s["topology"]["entities"]["pc-18"]["attached"] = {"device": "ACC-SW1", "interface": "Gi1/0/5", "vlan": 100}
    render_network(s, tmp_path / "off", no_icons)
    assert "## Documented MAC table" not in (tmp_path / "off" / "NETWORK.md").read_text()
    s["meta"]["mac_table"] = True
    man = render_network(s, tmp_path / "on", no_icons)
    text = (tmp_path / "on" / "NETWORK.md").read_text()
    assert "## Documented MAC table" in text and "| mac-pc-18 | 0000.5e00.5380 |" in text
    assert "doc:mac-pc-18" in man["NETWORK.md"]


def test_icon_lookup_falls_back_per_icon(tmp_path):
    from PIL import Image
    Image.new("RGB", (40, 30), "white").save(tmp_path / "router.jpg")
    (tmp_path / "layer 3 switch.jpg").write_bytes(b"not a jpeg")
    assert icon_source("router", tmp_path) == tmp_path / "router.jpg"
    assert load_icon("router", tmp_path) is not None
    assert load_icon("l3switch", tmp_path) is None          # corrupt file -> built-in
    assert load_icon("switch", tmp_path) is None             # missing file -> built-in
    rep = icon_report(tmp_path)
    assert rep["router"] == "router.jpg" and rep["switch"] == "built-in"
    assert set(CISCO_FILES) == set(KINDS)


def test_renders_with_real_icon_folder_shape(tmp_path):
    from PIL import Image
    icons = tmp_path / "icons"
    icons.mkdir()
    for kind, names in CISCO_FILES.items():
        Image.new("RGB", (60, 40), "white").save(icons / names[0])
    render_network(copy.deepcopy(STP), tmp_path / "out", icons)
    assert (tmp_path / "out" / "topology.png").exists()
