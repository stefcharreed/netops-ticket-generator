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
