"""D checks: documented overrides (docs vs gear) and doc refs in the answer key."""
import copy
from pathlib import Path

from packetgen.registry import load_registry
from packetgen.spec import load_spec
from packetgen.validate import validate

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = load_spec(ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json")


def spec() -> dict:
    return copy.deepcopy(CLEAN)


def errors(s: dict) -> set[str]:
    return {f["check"] for f in validate(s, REG) if f["severity"] == "error"}


def with_override(s: dict, kind: str = "red_herring") -> dict:
    s["topology"]["entities"]["dhcp-relay"]["documented"] = {"ip": "10.20.20.9"}
    s["answer"]["doc_mismatch"] = {"ref": "doc:dhcp-relay", "kind": kind, "note": "docs list the old relay IP"}
    return s


def test_clean_fixture_has_no_d_errors():
    assert not {c for c in errors(spec()) if c.startswith("D")}


def test_valid_red_herring_passes():
    assert not {c for c in errors(with_override(spec())) if c.startswith("D")}


def test_d1_more_than_one_override():
    s = with_override(spec())
    s["topology"]["devices"][0]["documented"] = {"mgmt_ip": "10.0.0.99"}
    assert "D1" in errors(s)


def test_d2_override_without_mismatch_and_mismatch_without_override():
    s = with_override(spec())
    del s["answer"]["doc_mismatch"]
    assert "D2" in errors(s)
    s = spec()
    s["answer"]["doc_mismatch"] = {"ref": "doc:dhcp-relay", "kind": "red_herring", "note": "x"}
    assert "D2" in errors(s)


def test_d2_ref_must_point_at_the_overridden_row():
    s = with_override(spec())
    s["answer"]["doc_mismatch"]["ref"] = "doc:client-a"
    assert "D2" in errors(s)


def test_d2_documented_equal_to_real_is_not_an_override():
    s = spec()
    s["topology"]["entities"]["dhcp-relay"]["documented"] = {"ip": "10.20.20.1"}
    s["answer"]["doc_mismatch"] = {"ref": "doc:dhcp-relay", "kind": "red_herring", "note": "x"}
    assert "D2" in errors(s)


def test_d3_attached_device_must_exist():
    s = spec()
    s["topology"]["entities"]["client-a"]["attached"] = {"device": "NOPE-SW9", "interface": "Gi1/0/5"}
    assert "D3" in errors(s)
    s["topology"]["entities"]["client-a"]["attached"]["device"] = "ACC-SW2"
    assert "D3" not in errors(s)


def test_d4_cause_needs_the_documented_value_in_the_root_cause():
    s = with_override(spec(), "cause")
    assert "D4" in errors(s)
    cd1 = next(c for c in s["config_diffs"] if c["id"] == "cd1")
    cd1["after"] += " ip helper-address 10.20.20.9\n"
    assert "D4" not in errors(s)


def test_k1_accepts_existing_doc_refs_only():
    s = spec()
    s["answer"]["rubric"][0]["evidence_refs"].append("doc:ACC-SW1-mgmt")
    assert "K1" not in errors(s)
    s["answer"]["rubric"][0]["evidence_refs"].append("doc:nope")
    assert "K1" in errors(s)
