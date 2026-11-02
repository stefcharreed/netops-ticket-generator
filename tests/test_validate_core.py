"""Task 5: registry (R), time (T) and causality (C) rules.

Each test mutates a deep copy of the clean fixture and asserts the rule's check id fires.
Run one rule at a time:  pytest tests/test_validate_core.py -k R1
"""
import copy
from pathlib import Path

import pytest

from packetgen.registry import load_registry
from packetgen.spec import load_spec
from packetgen.validate import validate

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = load_spec(ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json")


def spec() -> dict:
    return copy.deepcopy(CLEAN)


def ev(s: dict, eid: str) -> dict:
    return next(e for e in s["events"] if e["id"] == eid)


def errors(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "error"}


def warnings(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "warning"}


def test_clean_fixture_no_errors():
    assert errors(spec()) == set()


def test_schema_errors_short_circuit():
    s = spec()
    s["meta"]["id"] = "not-an-id"
    assert {f["check"] for f in validate(s, REG)} == {"S0"}


# --- R: registry ---------------------------------------------------------------

def test_R1_unknown_format_id():
    s = spec()
    ev(s, "e5")["format_id"] = "IOS:NOPE-1-NOPE"
    assert "R1" in errors(s)


def _unverified_ios_id() -> str:
    return next(i for i, e in REG.items() if not e["verified"] and e["header_style"] == "ios")


def test_R2_unverified_is_error_by_default():
    s = spec()
    ev(s, "e5")["format_id"] = _unverified_ios_id()
    assert "R2" in errors(s)


def test_R2_unverified_is_warning_when_allowed():
    s = spec()
    s["meta"]["allow_unverified"] = True
    ev(s, "e5")["format_id"] = _unverified_ios_id()
    assert "R2" in warnings(s) and "R2" not in errors(s)


def test_R3_missing_field_is_error():
    s = spec()
    del ev(s, "e5")["fields"]["state"]
    assert "R3" in errors(s)


def test_R3_extra_field_is_warning():
    s = spec()
    ev(s, "e5")["fields"]["vlan"] = "20"
    assert "R3" in warnings(s) and "R3" not in errors(s)


def test_R3_half_filled_optional_section_is_a_finding_not_a_crash():
    import re
    fid, entry, names = next(
        (i, e, n) for i, e in REG.items()
        for sec in re.findall(r"\[\[(.*?)\]\]", e["message"])
        if len(n := re.findall(r"\{(\w+)\}", sec)) >= 2)
    required = set(re.findall(r"\{(\w+)\}", re.sub(r"\[\[.*?\]\]", "", entry["message"])))
    s = spec()
    ev(s, "e5")["format_id"] = fid
    ev(s, "e5")["fields"] = {**{n: "x" for n in required}, names[0]: "x"}
    assert "R3" in errors(s)


def test_R4_value_breaks_pattern():
    s = spec()
    ev(s, "e5")["fields"]["state"] = "sideways"
    assert "R4" in errors(s)


def test_R5_header_style_mismatch():
    s = spec()
    next(d for d in s["topology"]["devices"] if d["hostname"] == "DHCP01")["header_style"] = "ios"
    assert "R5" in errors(s)


# --- T: time -------------------------------------------------------------------

def test_T1_naive_timestamp():
    s = spec()
    ev(s, "e3")["t"] = "2025-06-01 12:01:40"
    assert "T1" in errors(s)


def test_T2_event_outside_window():
    s = spec()
    ev(s, "e8")["t"] = "2025-06-01T12:07:00Z"
    assert "T2" in errors(s)


def test_T2_window_is_inclusive():
    s = spec()
    ev(s, "e8")["t"] = s["meta"]["window"]["end"]
    assert "T2" not in errors(s)


def test_T2_change_after_window_end():
    s = spec()
    s["config_diffs"][0]["t_change"] = "2025-06-01T12:10:00Z"
    assert "T2" in errors(s)


def test_T3_effect_before_cause():
    s = spec()
    ev(s, "e4")["t"] = "2025-06-01T12:00:30Z"  # parent e2 is 12:01:05
    assert "T3" in errors(s)


def test_T4_change_after_first_symptom():
    s = spec()
    s["config_diffs"][0]["t_change"] = "2025-06-01T12:00:20Z"  # e1 is 12:00:12
    assert "T4" in errors(s)


# --- C: causality --------------------------------------------------------------

def test_C1_root_missing():
    s = spec()
    s["answer"]["root_cause_id"] = "e99"
    assert "C1" in errors(s)


def test_C1_second_root_label():
    s = spec()
    ev(s, "e3")["label"] = "root_cause"
    assert "C1" in errors(s)


def test_C2_chain_does_not_reach_root():
    s = spec()
    ev(s, "e7")["caused_by"] = "e3"  # e3 is unrelated with no parent
    assert "C2" in errors(s)


def test_C2_dangling_parent():
    s = spec()
    ev(s, "e7")["caused_by"] = "e42"
    assert "C2" in errors(s)


def test_C2_cycle():
    s = spec()
    ev(s, "e2")["caused_by"] = "e4"  # e4 already points at e2
    assert "C2" in errors(s)


def test_C3_noise_with_parent():
    s = spec()
    ev(s, "e5")["caused_by"] = "e2"
    assert "C3" in errors(s)


@pytest.mark.parametrize("chain", [["e2", "cd1", "e4"], ["cd1", "e4", "e2"]])
def test_C4_chain_bad_start_or_order(chain):
    s = spec()
    s["answer"]["chain"] = chain
    assert "C4" in errors(s)
