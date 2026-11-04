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


def test_no_tshark_sanitizes_flow_string_params(tmp_path):
    spec = json.loads(FIXTURE.read_text())
    spec["capture"]["flows"][2]["params"]["name"] = f"{PUBLIC_IP}.example.com"
    out, spec_path = setup(tmp_path, spec)
    result = build_packet(spec_path, out, ROOT / "registry", DAY, use_tshark=False)
    assert not result["ok"] and "Z1" in checks(result), result["findings"]
