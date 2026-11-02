import json
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import packetgen.build as build_mod
from packetgen.build import build_packet
from packetgen.findings import finding

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json"
DAY = date(2026, 10, 22)


def setup_out(tmp_path: Path) -> tuple[Path, Path]:
    out = tmp_path / "packet output"
    keys = out / "Keys"
    keys.mkdir(parents=True)
    spec_path = keys / "pkt-0a1b2c.json"
    shutil.copy(FIXTURE, spec_path)
    return out, spec_path


def test_build_happy_path_space_in_path(tmp_path):
    out, spec_path = setup_out(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    packet = out / "2026-10-22-pkt-0a1b2c"
    assert result["packet_dir"] == str(packet)
    for name in ("BRIEF.md", "logs.xlsx", "config_diffs.txt", "telemetry_DIST-SW1.png"):
        assert (packet / name).exists(), name
    manifest = json.loads((out / "Keys" / "pkt-0a1b2c.manifest.json").read_text())
    assert manifest["logs.xlsx"]["e1"] >= 2


def test_build_refuses_existing_without_force(tmp_path):
    out, spec_path = setup_out(tmp_path)
    assert build_packet(spec_path, out, ROOT / "registry", DAY)["ok"]
    again = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not again["ok"] and "B1" in {f["check"] for f in again["findings"]}
    assert build_packet(spec_path, out, ROOT / "registry", DAY, force=True)["ok"]


def test_build_refuses_same_id_on_a_later_day(tmp_path):
    out, spec_path = setup_out(tmp_path)
    assert build_packet(spec_path, out, ROOT / "registry", DAY)["ok"]
    later = build_packet(spec_path, out, ROOT / "registry", date(2026, 10, 23))
    assert not later["ok"] and "B1" in {f["check"] for f in later["findings"]}
    assert sorted(p.name for p in out.iterdir()) == ["2026-10-22-pkt-0a1b2c", "Keys"]


def test_force_replaces_earlier_day_folder(tmp_path):
    out, spec_path = setup_out(tmp_path)
    assert build_packet(spec_path, out, ROOT / "registry", DAY)["ok"]
    assert build_packet(spec_path, out, ROOT / "registry", date(2026, 10, 23), force=True)["ok"]
    assert sorted(p.name for p in out.iterdir()) == ["2026-10-23-pkt-0a1b2c", "Keys"]


def test_manifest_records_packet_dir(tmp_path):
    out, spec_path = setup_out(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    manifest = json.loads((out / "Keys" / "pkt-0a1b2c.manifest.json").read_text())
    assert manifest["packet_dir"] == result["packet_dir"]


def test_build_lists_ticket_in_brief(tmp_path):
    out, spec_path = setup_out(tmp_path)
    data = json.loads(spec_path.read_text())
    data["ticket"] = json.loads((ROOT / "tests" / "fixtures" / "ticket.json").read_text())
    spec_path.write_text(json.dumps(data))
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    packet = out / "2026-10-22-pkt-0a1b2c"
    assert (packet / "TICKET.md").exists()
    files = (packet / "BRIEF.md").read_text().split("## Files")[1].split("## Deliverable")[0]
    assert "- TICKET.md" in files
    assert result["manifest"]["TICKET.md"] == {"ticket": "TICKET.md"}


def test_build_without_ticket_unchanged(tmp_path):
    out, spec_path = setup_out(tmp_path)
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert result["ok"], result["findings"]
    packet = out / "2026-10-22-pkt-0a1b2c"
    assert not (packet / "TICKET.md").exists()
    assert "TICKET" not in (packet / "BRIEF.md").read_text()
    assert result["manifest"]["TICKET.md"] == {}


def test_validation_failure_writes_nothing(tmp_path):
    out, spec_path = setup_out(tmp_path)
    data = json.loads(spec_path.read_text())
    data["meta"]["difficulty"]["min_noise"] = 9
    spec_path.write_text(json.dumps(data))
    assert not build_packet(spec_path, out, ROOT / "registry", DAY)["ok"]
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_failed_postcheck_leaves_no_dir(tmp_path, monkeypatch):
    out, spec_path = setup_out(tmp_path)
    monkeypatch.setattr(build_mod, "sanitize_findings",
                        lambda text, where: [finding("Z1", f"{where}: planted", "fix")])
    result = build_packet(spec_path, out, ROOT / "registry", DAY)
    assert not result["ok"] and result["packet_dir"] is None
    assert sorted(p.name for p in out.iterdir()) == ["Keys"]


def test_cli_exit_codes(tmp_path):
    env_py = [sys.executable, "-m", "packetgen"]
    ok = subprocess.run(env_py + ["validate", str(FIXTURE), "--registry", str(ROOT / "registry")],
                        capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = tmp_path / "bad.json"
    data = json.loads(FIXTURE.read_text())
    data["meta"]["id"] = "nope"
    bad.write_text(json.dumps(data))
    fail = subprocess.run(env_py + ["validate", str(bad), "--registry", str(ROOT / "registry")],
                          capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")})
    assert fail.returncode == 1 and "S0" in fail.stdout
