import json
import os
import shutil
import struct
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from packetgen import capture_kinds, tshark
from packetgen.build import build_packet

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "radius_capture.json"
OLD_FIXTURE = ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json"
DAY = date(2026, 11, 4)
PCAP = "capture_ACC-SW1_Gi1-0-48.pcap"
PUBLIC_IP = ".".join(["8", "8", "4", "4"])  # assembled so this file passes the sanitize gate it tests
VENDOR_MAC = ":".join(["00", "1b", "54", "00", "00", "01"])


@pytest.fixture
def need_tshark():
    if shutil.which("tshark") is None:
        if os.environ.get("PACKETGEN_REQUIRE_TSHARK") == "1":
            pytest.fail("tshark required (PACKETGEN_REQUIRE_TSHARK=1) but not on PATH")
        pytest.skip("tshark not installed")


def setup(tmp_path: Path, spec: dict | None = None) -> tuple[Path, Path]:
    out = tmp_path / "packet output"
    keys = out / "Keys"
    keys.mkdir(parents=True)
    path = keys / "pkt-5ca9e1.json"
    if spec is None:
        shutil.copy(FIXTURE, path)
    else:
        path.write_text(json.dumps(spec))
    return out, path


def checks(result: dict) -> set[str]:
    return {f["check"] for f in result["findings"]}


def test_build_capture_happy_path(tmp_path, need_tshark):
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    packet = out / "2026-11-04-pkt-5ca9e1"
    assert (packet / PCAP).exists()
    manifest = json.loads(spec_path.with_suffix(".manifest.json").read_text())
    assert len(manifest[PCAP]["pk1"]) == 4
    assert manifest["tshark_checked"] is True
    assert "SPAN on ACC-SW1 Gi1/0/48 (toward DIST-SW1), both directions, 14:00–14:10 UTC." in (
        packet / "BRIEF.md").read_text()


def test_tshark_env_is_hermetic(monkeypatch, need_tshark):
    seen = {}
    real = subprocess.run

    def spy(argv, **kw):
        seen.update(argv=argv, env=kw["env"], exists=Path(kw["env"]["WIRESHARK_CONFIG_DIR"]).is_dir())
        return real(argv, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    monkeypatch.setenv("WIRESHARK_CONFIG_DIR", "/nonexistent/personal-profile")
    proc = tshark._run(["-G", "folders"])
    cfg = seen["env"]["WIRESHARK_CONFIG_DIR"]
    assert seen["argv"][0] == "tshark" and seen["env"]["TZ"] == "UTC" and seen["exists"]
    assert cfg != "/nonexistent/personal-profile" and not Path(cfg).exists()  # fresh per call, then removed
    assert cfg in proc.stdout  # tshark really uses it as the personal configuration folder


def test_rendered_fixture_is_clean_and_pk1_unanswered_filter_matches(tmp_path, need_tshark):
    pytest.importorskip("dpkt")
    from packetgen.render.capture import render_capture
    spec = json.loads(FIXTURE.read_text())
    pk = render_capture(spec, tmp_path)
    rb = tshark.read_back(tmp_path / PCAP, {"pk1": "radius.code == 1 && !radius.rspframe"})
    assert rb["filter_errors"] == {} and rb["bad_frames"] == []  # zero malformed / expert-error rows
    assert rb["matches"]["pk1"] == pk["pk1"] and len(pk["pk1"]) == 4


def test_read_back_planted_bad_frame(tmp_path, need_tshark):
    frame = bytes.fromhex("00005e005301" "00005e005302" "0800") + bytes.fromhex("4500002800010000400600000a000001")
    pcap = tmp_path / "bad.pcap"
    pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)
    r = tshark.read_back(pcap, {})
    assert r["frames"] == 1 and r["bad_frames"] == [1]


def test_pk6_filter_miss(tmp_path, monkeypatch, need_tshark):
    monkeypatch.setattr(capture_kinds, "expected_filter", lambda fl: "radius.code == 2")
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK6" in checks(result)
    assert result["packet_dir"] is None


def test_build_capture_without_tshark(tmp_path, monkeypatch):
    monkeypatch.setattr(tshark, "tshark_version", lambda: None)
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK6" in checks(result)
    assert not list(out.glob("2026-*"))


def test_build_capture_old_tshark(tmp_path, monkeypatch):
    monkeypatch.setattr(tshark, "tshark_version", lambda: (4, 0, 0))
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK6" in checks(result)


def test_build_capture_without_dpkt(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "dpkt", None)
    monkeypatch.delitem(sys.modules, "packetgen.render.capture", raising=False)
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and checks(result) == {"PK0"}, result["findings"]
    assert [f["check"] for f in result["findings"]] == ["PK0"]
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_pk7_frame_cap(tmp_path):
    spec = json.loads(FIXTURE.read_text())
    spec["meta"]["window"]["end"] = "2026-10-20T17:25:00Z"
    spec["capture"]["end"] = "2026-10-20T17:00:00Z"
    spec["capture"]["noise"] = "high"
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK7" in checks(result), result["findings"]


def test_no_tshark_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(tshark, "tshark_version", lambda: None)  # would fail PK6 if it ran
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY, use_tshark=False)
    assert result["ok"], result["findings"]
    pk6 = [f for f in result["findings"] if f["check"] == "PK6"]
    assert pk6 and all(f["severity"] == "warning" for f in pk6)
    assert json.loads(spec_path.with_suffix(".manifest.json").read_text())["tshark_checked"] is False


def test_build_without_capture_unchanged(tmp_path):
    out = tmp_path / "packet output"
    (out / "Keys").mkdir(parents=True)
    spec_path = out / "Keys" / "pkt-0a1b2c.json"
    shutil.copy(OLD_FIXTURE, spec_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    brief = (out / "2026-11-04-pkt-0a1b2c" / "BRIEF.md").read_text()
    assert "## Capture" not in brief and "capture frame numbers" not in brief
    assert "citing log ids, chart minutes\n  and config diff lines.\n" in brief
    assert "tshark_checked" not in spec_path.with_suffix(".manifest.json").read_text()


@pytest.mark.parametrize("exc", [FileNotFoundError("tshark"), subprocess.TimeoutExpired("tshark", 1)])
def test_tshark_vanishes_or_hangs(tmp_path, monkeypatch, exc):
    monkeypatch.setattr(tshark, "tshark_version", lambda: (4, 6, 9))

    def boom(args):
        raise exc

    monkeypatch.setattr(tshark, "_run", boom)
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK6" in checks(result)
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_failed_dump_is_pk6(tmp_path, monkeypatch, need_tshark):
    real = tshark._run

    def run(args):
        if "-V" in args:
            return subprocess.CompletedProcess(args, 1, "", "dump failed")
        return real(args)

    monkeypatch.setattr(tshark, "_run", run)
    out, spec_path = setup(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and "PK6" in checks(result)
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_no_tshark_still_sanitizes_capture_addresses(tmp_path):
    spec = json.loads(FIXTURE.read_text())
    spec["topology"]["devices"][0]["interfaces"].append(
        {"name": "Gi1/0/2", "ip": PUBLIC_IP, "mac": VENDOR_MAC})
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY, use_tshark=False)
    assert not result["ok"], result["findings"]
    assert {"Z1", "Z2"} <= checks(result)
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_no_tshark_sanitizes_noise_only_entity(tmp_path):
    from packetgen.render.capture import build_frames
    spec = json.loads(FIXTURE.read_text())
    spec["topology"]["entities"]["camera-3"] = {"ip": "10.10.100.70", "mac": VENDOR_MAC}  # anchored /24, no flow
    mac = bytes.fromhex(VENDOR_MAC.replace(":", ""))
    assert any(mac in buf for _, buf in build_frames(spec)[0]), "entity must reach the implicit noise"
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY, use_tshark=False)
    assert not result["ok"] and "Z2" in checks(result), result["findings"]
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_no_tshark_sanitizes_flow_string_params(tmp_path):
    spec = json.loads(FIXTURE.read_text())
    spec["capture"]["flows"][2]["params"]["name"] = f"{PUBLIC_IP}.example.com"
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY, use_tshark=False)
    assert not result["ok"] and "Z1" in checks(result), result["findings"]


TRUNK = ROOT / "tests" / "fixtures" / "trunk_pruned_capture.json"


def test_trunk_pruned_fixture_validates_clean():
    from packetgen.registry import load_registry
    from packetgen.validate import validate
    spec = json.loads(TRUNK.read_text())
    assert [f for f in validate(spec, load_registry(ROOT / "registry")) if f["severity"] == "error"] == []


def test_build_trunk_pruned_tshark(tmp_path, need_tshark):
    out, spec_path = setup(tmp_path, json.loads(TRUNK.read_text()))
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    assert "PK6" not in checks(result)
    pcap = next((out).glob("*/capture_ACC-SW1_Gi1-0-48.pcap"))
    manifest = json.loads(spec_path.with_suffix(".manifest.json").read_text())
    rb = tshark.read_back(pcap, {"pk1": "(arp.opcode == 1) && vlan.id == 30"})
    assert set(manifest[pcap.name]["pk1"]) <= set(rb["matches"]["pk1"])  # earlier VLAN-30 noise ARPs match too


def _radius_erspan() -> dict:
    spec = json.loads(FIXTURE.read_text())
    spec["topology"]["entities"]["analyzer-1"] = {"ip": "10.30.0.5", "mac": "00:00:5e:00:53:30"}
    cap = spec["capture"]
    cap["method"] = "erspan"
    del cap["span"]
    cap["erspan"] = {"origin_ip": "10.10.100.2", "analyzer": "analyzer-1", "session": 1, "erspan_id": 100,
                     "via": "DIST-SW1:Vlan100"}
    cap["reason"] = ("ERSPAN from ACC-SW1 Gi1/0/48: the analyzer sits in the data center, a routed hop away, "
                     "so a local SPAN can't reach it.")
    return spec


def test_build_radius_erspan_tshark(tmp_path, need_tshark):
    out, spec_path = setup(tmp_path, _radius_erspan())
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    assert "PK6" not in checks(result)
    pcap = next(out.glob(f"*/{PCAP}"))
    manifest = json.loads(spec_path.with_suffix(".manifest.json").read_text())
    rb = tshark.read_back(pcap, {"pk1": "(radius.code == 1 && !radius.rspframe) && erspan"})
    assert rb["bad_frames"] == [] and set(rb["matches"]["pk1"]) == set(manifest[PCAP]["pk1"])
    assert len(manifest[PCAP]["pk1"]) == 4


def test_pk6_filter_gets_encapsulation_suffix(tmp_path, monkeypatch, need_tshark):
    seen = {}
    real = tshark.read_back

    def spy(pcap, filters):
        seen.update(filters)
        return real(pcap, filters)

    monkeypatch.setattr(tshark, "read_back", spy)
    out, spec_path = setup(tmp_path, _radius_erspan())
    build_packet(spec_path, out, ROOT / "registry", DAY)
    assert seen["pk1"] == "(radius.code == 1 && !radius.rspframe) && erspan"


# --- phase 2 pattern fixtures ---------------------------------------------------------------

L2 = {  # fixture -> (symptom pk, spot-check filter, the pk ids that filter must match)
    "loop_bpdufilter": ("pk1", "stp && eth.src == 00:00:5e:00:53:16", ["pk1"]),
    "port_security": ("pk3", "arp && eth.src == 00:00:5e:00:53:85", ["pk3"]),
    "native_vlan": ("pk2", "cdp.native_vlan == 99 && vlan.id == 1", ["pk2"]),
    "hsrp_flap": ("pk3", "hsrp.state == 16 && eth.src == 00:00:0c:07:ac:0a", ["pk3", "pk5"]),
}


def _fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"{name}_capture.json").read_text())


@pytest.mark.parametrize("name", list(L2))
def test_l2_fixture_validates_clean(name):
    from packetgen.registry import load_registry
    from packetgen.validate import validate
    found = validate(_fixture(name), load_registry(ROOT / "registry"))
    assert [f for f in found if f["severity"] == "error"] == []


@pytest.mark.parametrize("name", list(L2))
def test_build_l2_fixture_tshark(tmp_path, need_tshark, name):
    from packetgen.capture import capture_filename
    from packetgen.capture_views import filter_suffix
    spec = _fixture(name)
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    assert "PK6" not in checks(result)
    pcap = next(out.glob(f"*/{capture_filename(spec)}"))
    frames = json.loads(spec_path.with_suffix(".manifest.json").read_text())[pcap.name]
    symptoms = {fl["id"]: fl for fl in spec["capture"]["flows"] if fl["label"] == "symptom"}
    sym, spot, spot_pks = L2[name]
    filters = {fid: f"({capture_kinds.expected_filter(fl)}){filter_suffix(spec, fl)}" for fid, fl in symptoms.items()}
    rb = tshark.read_back(pcap, {**filters, "spot": spot})
    assert rb["bad_frames"] == []
    for fid in symptoms:
        assert set(frames[fid]) <= set(rb["matches"][fid]), fid
    assert sym in symptoms and all(set(frames[p]) <= set(rb["matches"]["spot"]) for p in spot_pks)


def test_port_security_capture_goes_silent(tmp_path):
    pytest.importorskip("dpkt")
    import dpkt
    from packetgen.capture import capture_filename
    from packetgen.render.capture import render_capture
    from packetgen.timebase import parse_utc
    spec = _fixture("port_security")
    render_capture(spec, tmp_path)
    cut = parse_utc(next(e["t"] for e in spec["events"] if e["id"] == "e3")).timestamp()
    with (tmp_path / capture_filename(spec)).open("rb") as f:
        times = [ts for ts, _ in dpkt.pcap.Reader(f)]
    assert times and max(times) < cut
