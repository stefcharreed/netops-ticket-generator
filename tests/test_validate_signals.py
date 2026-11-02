"""Task 6: telemetry (S), entity (E), key (K), leak (L), noise (N), quiet-root (Q)."""
import copy
import json
from pathlib import Path

from packetgen.registry import load_registry
from packetgen.spec import load_spec
from packetgen.validate import validate

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = load_spec(ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json")
TICKET = json.loads((ROOT / "tests" / "fixtures" / "ticket.json").read_text())


def spec() -> dict:
    return copy.deepcopy(CLEAN)


def ev(s: dict, eid: str) -> dict:
    return next(e for e in s["events"] if e["id"] == eid)


def series(s: dict, sid: str) -> dict:
    return next(t for t in s["telemetry"] if t["id"] == sid)


def errors(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "error"}


def warnings(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "warning"}


def cpu(sid: str, metric: str, peak: float) -> dict:
    t = [f"2025-06-01T12:0{i}:00Z" for i in range(6)]
    vals = [10, 10, peak, 10, 10, 10]
    return {"id": sid, "device": "DIST-SW1", "metric": metric, "kind": "gauge", "unit": "%",
            "interval_s": 60, "points": [[a, b] for a, b in zip(t, vals)]}


# --- S: telemetry ----------------------------------------------------------------

def test_S1_uneven_spacing():
    s = spec()
    series(s, "tm1")["points"][1][0] = "2025-06-01T12:01:30Z"
    assert "S1" in errors(s)


def test_S2_error_counter_must_be_rate_or_delta():
    s = spec()
    series(s, "tm2")["kind"] = "gauge"
    assert "S2" in errors(s)


def test_S2_negative_rate():
    s = spec()
    series(s, "tm2")["points"][3][1] = -4
    assert "S2" in errors(s)


def test_S3_longer_window_peaks_higher():
    s = spec()
    s["telemetry"].append(cpu("tm3", "cpu_5min", 70))  # tm1 cpu_1min peaks at 61
    assert "S3" in errors(s)


def test_S3_cpu_window_ordering_ok():
    s = spec()
    s["telemetry"] += [cpu("tm3", "cpu_5s", 95), cpu("tm4", "cpu_5min", 16)]
    assert "S3" not in errors(s)


def test_S4_signal_not_in_series():
    s = spec()
    ev(s, "e4")["signal"]["value"] = 90  # tm1 never reaches 90
    assert "S4" in errors(s)


def test_S4_signal_series_on_other_device():
    s = spec()
    series(s, "tm1")["device"] = "CORE-SW1"
    assert "S4" in errors(s)


# --- E: entities -------------------------------------------------------------------

def test_E1_unknown_device():
    s = spec()
    ev(s, "e5")["device"] = "ACC-SW9"
    assert "E1" in errors(s)


def test_E2_undeclared_mac():
    s = spec()
    ev(s, "e7")["fields"]["mac"] = "00:00:5e:00:53:99"
    assert "E2" in errors(s)


# --- K: answer key -------------------------------------------------------------------

def test_K1_unknown_evidence_ref():
    s = spec()
    s["answer"]["rubric"][0]["evidence_refs"] = ["e77"]
    assert "K1" in errors(s)


def test_K2_duplicate_rubric_id():
    s = spec()
    s["answer"]["rubric"][1]["id"] = "r1"
    assert "K2" in errors(s)


# --- L: leaks ------------------------------------------------------------------------

def test_L1_term_in_brief():
    s = spec()
    s["meta"]["brief"] += " Check the BPDUfilter settings."
    assert "L1" in errors(s)


def test_L1_term_in_visible_note():
    s = spec()
    s["meta"]["difficulty"]["show_diff_notes"] = True
    s["config_diffs"][0]["note"] = "enabled bpdufilter"
    assert "L1" in errors(s)


def test_L1_hidden_note_is_fine():
    s = spec()
    s["config_diffs"][0]["note"] = "enabled bpdufilter"
    assert "L1" not in errors(s)


# --- N / Q ---------------------------------------------------------------------------

def test_N1_not_enough_noise():
    s = spec()
    s["meta"]["difficulty"]["min_noise"] = 5  # fixture has 4 unrelated/noise events
    assert "N1" in errors(s)


def test_Q1_root_is_loudest_event_warns():
    s = spec()
    s["answer"]["root_cause_id"] = "e4"  # SYS-1 is the most severe line in the packet
    ev(s, "e4")["label"] = "root_cause"
    assert "Q1" in warnings(s)


# --- ticket (P4) --------------------------------------------------------------------

def ticket_spec(text: str) -> dict:
    s = spec()
    s["ticket"] = {**copy.deepcopy(TICKET), "text": text}
    return s


def test_validate_runs_ticket_checks():
    s = ticket_spec("Since this morning ZZ-SW9 keeps dropping. It worked fine after lunch yesterday.")
    assert "TK1" in errors(s)


def test_L1_ticket_text():
    s = ticket_spec("The BPDUFilter thing again. It worked fine after lunch yesterday.")
    msgs = [f["message"] for f in validate(s, REG) if f["check"] == "L1"]
    assert any(m.startswith("ticket.text gives away") for m in msgs)


def test_no_ticket_validates_clean():
    assert "ticket" not in CLEAN
    assert errors(spec()) == set()
