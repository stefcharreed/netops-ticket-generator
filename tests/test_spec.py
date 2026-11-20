import copy
from pathlib import Path

from packetgen.spec import load_spec, schema_findings

FIXTURE = Path(__file__).parent / "fixtures" / "stp_dhcp_cascade.json"


def fixture() -> dict:
    return copy.deepcopy(load_spec(FIXTURE))


def test_fixture_is_schema_valid():
    assert schema_findings(fixture()) == []


def test_bad_id_pattern():
    spec = fixture()
    spec["meta"]["id"] = "stp-root"
    found = schema_findings(spec)
    assert [f["check"] for f in found] == ["S0"]
    assert "meta" in found[0]["message"]


def test_unsynced_requires_skew():
    spec = fixture()
    dev = spec["topology"]["devices"][0]
    dev["clock"] = "unsynced"
    dev.pop("skew_s", None)
    assert [f["check"] for f in schema_findings(spec)] == ["S0"]


def test_unknown_top_level_key_rejected():
    spec = fixture()
    spec["answers"] = {}
    assert [f["check"] for f in schema_findings(spec)] == ["S0"]


FIXTURE_CAPTURE = Path(__file__).parent / "fixtures" / "radius_capture.json"


def capture_fixture() -> dict:
    return copy.deepcopy(load_spec(FIXTURE_CAPTURE))


def test_capture_fixture_schema_clean():
    assert schema_findings(capture_fixture()) == []


def test_root_cannot_be_flow():
    spec = capture_fixture()
    spec["answer"]["root_cause_id"] = "pk1"
    assert "S0" in [f["check"] for f in schema_findings(spec)]


def test_event_caused_by_flow_rejected():
    spec = capture_fixture()
    spec["events"][1]["caused_by"] = "pk1"
    assert "S0" in [f["check"] for f in schema_findings(spec)]


def test_flow_root_label_rejected():
    spec = capture_fixture()
    spec["capture"]["flows"][0]["label"] = "root_cause"
    assert "S0" in [f["check"] for f in schema_findings(spec)]


def test_existing_fixture_still_clean():
    assert "S0" not in [f["check"] for f in schema_findings(fixture())]


def _msgs(spec: dict) -> str:
    return "\n".join(f["message"] for f in schema_findings(spec))


def test_old_tagged_spec_rejected():
    s = capture_fixture()
    cap = s["capture"]
    for k in ("method", "reason", "span"):
        cap.pop(k, None)
    cap["tagged"] = False
    msgs = _msgs(s)
    assert "'tagged'" in msgs
    assert "'method' is a required property" in msgs


def test_span_method_requires_span_block():
    s = capture_fixture()
    del s["capture"]["span"]
    assert schema_findings(s)


def test_erspan_block_forbidden_under_span():
    s = capture_fixture()
    s["capture"]["erspan"] = {"origin_ip": "10.10.100.2", "analyzer": "analyzer-1", "session": 1, "erspan_id": 100}
    assert schema_findings(s)


def test_replicate_requires_trunk_vlans():
    s = capture_fixture()
    s["capture"]["span"] = {"encapsulation": "replicate"}
    assert schema_findings(s)
    s["capture"]["span"]["trunk_vlans"] = [1, 30]
    assert schema_findings(s) == []


def test_reason_bounds():
    s = capture_fixture()
    s["capture"]["reason"] = "ACC-SW1 short reason"[:19]
    assert schema_findings(s)
    s["capture"]["reason"] = "ACC-SW1 uplink SPAN,\nboth sides of the conversation"
    assert schema_findings(s)
