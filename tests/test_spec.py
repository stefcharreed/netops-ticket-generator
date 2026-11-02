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
