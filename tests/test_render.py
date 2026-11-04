import copy
import json
from pathlib import Path

import openpyxl

from packetgen.registry import load_registry
from packetgen.render.brief import render_brief
from packetgen.render.configs import render_configs
from packetgen.render.logs import render_logs
from packetgen.render.telemetry import render_telemetry
from packetgen.render.ticket import render_ticket
from packetgen.spec import load_spec

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = load_spec(ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json")


def spec() -> dict:
    return copy.deepcopy(CLEAN)


def test_logs_rows_and_dates(tmp_path):
    s = spec()
    manifest = render_logs(s, REG, tmp_path)
    ws = openpyxl.load_workbook(tmp_path / "logs.xlsx").active
    assert ws is not None
    rows = list(ws.iter_rows())
    assert [c.value for c in rows[0]] == ["log_id", "received_utc", "host", "message"]
    assert len(rows) == 1 + len(s["events"])
    assert all(r[1].is_date for r in rows[1:])
    assert set(manifest) == {e["id"] for e in s["events"]}
    e1_row = rows[manifest["e1"] - 1]
    assert e1_row[2].value == "ACC-SW2"
    assert e1_row[3].value.startswith("Jun  1 12:00:12.000 UTC: %SYS-5-CONFIG_I: Configured from console")


def test_shuffle_is_deterministic(tmp_path):
    s = spec()
    s["meta"]["difficulty"]["shuffle_rows"] = 3
    a = render_logs(s, REG, tmp_path / "a")
    b = render_logs(s, REG, tmp_path / "b")
    assert a == b


def test_telemetry_png_per_device(tmp_path):
    manifest = render_telemetry(spec(), tmp_path)
    assert manifest == {"tm1": "telemetry_DIST-SW1.png", "tm2": "telemetry_DIST-SW1.png"}
    assert (tmp_path / "telemetry_DIST-SW1.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_diff_notes_hidden_by_default(tmp_path):
    s = spec()
    manifest = render_configs(s, tmp_path)
    text = (tmp_path / "config_diffs.txt").read_text()
    assert "! NOTE" not in text and "+ spanning-tree bpdufilter enable" in text
    assert text.splitlines()[manifest["cd1"] - 1].startswith("--- a/ACC-SW2/cd1")


def test_diff_shows_whole_stanza(tmp_path):
    render_configs(spec(), tmp_path)
    # The changed line is 5 lines below its interface header; default 3-line context hides which port it is.
    assert "\n interface GigabitEthernet1/0/48\n" in (tmp_path / "config_diffs.txt").read_text()


def test_diff_notes_shown_when_enabled(tmp_path):
    s = spec()
    s["meta"]["difficulty"]["show_diff_notes"] = True
    render_configs(s, tmp_path)
    assert "! NOTE: Conference room switch" in (tmp_path / "config_diffs.txt").read_text()


def test_brief_has_deliverables(tmp_path):
    render_brief(spec(), ["logs.xlsx", "config_diffs.txt"], tmp_path)
    text = (tmp_path / "BRIEF.md").read_text()
    assert "- logs.xlsx" in text
    assert "tag each log line as exactly one of root_cause, symptom, unrelated or noise." in text


def test_brief_capture_line(tmp_path):
    s = load_spec(ROOT / "tests" / "fixtures" / "radius_capture.json")
    render_brief(s, ["logs.xlsx"], tmp_path)
    text = (tmp_path / "BRIEF.md").read_text()
    assert "## Capture\nSPAN on ACC-SW1 Gi1/0/48 (toward DIST-SW1), both directions, 14:00–14:10 UTC.\n" in text
    assert "config diff lines and capture frame numbers." in text


TICKET = json.loads((ROOT / "tests" / "fixtures" / "ticket.json").read_text())


def spec_with_ticket() -> dict:
    s = spec()
    s["ticket"] = copy.deepcopy(TICKET)
    return s


def test_ticket_rendered(tmp_path):
    s = spec_with_ticket()
    assert render_ticket(s, tmp_path) == {"ticket": "TICKET.md"}
    text = (tmp_path / "TICKET.md").read_text()
    assert f"# Ticket TKT-{s['meta']['id']}" in text
    assert "**Reported by:** end user" in text
    assert TICKET["text"] in text


def test_misdirection_not_rendered(tmp_path):
    render_ticket(spec_with_ticket(), tmp_path)
    text = (tmp_path / "TICKET.md").read_text()
    for m in TICKET["misdirection"]:
        assert m["true_because"] not in text
        assert m["kind"] not in text
    assert "claim" not in text and "true_because" not in text


def test_no_ticket_no_file(tmp_path):
    assert render_ticket(spec(), tmp_path) == {}
    assert not (tmp_path / "TICKET.md").exists()
