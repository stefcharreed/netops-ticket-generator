from pathlib import Path

import pytest

from packetgen.registry import compile_pattern, load_registry, render_message

REGISTRY_DIR = Path(__file__).resolve().parent.parent / "registry"
STYLES = {"ios", "nxos", "asa", "bsd", "meraki", None}


@pytest.fixture(scope="module")
def reg():
    return load_registry(REGISTRY_DIR)


def test_render_link_updown(reg):
    out = render_message(reg["IOS:LINK-3-UPDOWN"], {"interface": "GigabitEthernet1/0/1", "state": "down"})
    assert out == "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down"


def test_inline_alternation_compiles(reg):
    pat = compile_pattern(reg["ASA:104001"])
    assert pat.search("%ASA-1-104001: (Secondary) Switching to ACTIVE - x.")
    assert pat.search("%ASA-1-104001: (Primary) Switching to ACTIVE - x.")
    assert not pat.search("%ASA-1-104001: (Tertiary) Switching to ACTIVE - x.")


def test_freetext_placeholder_matches_anything():
    entry = {"message": "Hello {who}, up {n}", "placeholders": {}}  # no regex for either
    pat = compile_pattern(entry)
    assert pat.search("Hello any thing (at all)!, up 3 days")
    assert pat.search("Hello , up 3")  # free text may be empty


def test_missing_field_raises():
    entry = {"message": "a {x} b {y}", "placeholders": {}}
    with pytest.raises(ValueError, match="y"):
        render_message(entry, {"x": "1"})


def test_fabricated_ids_absent_or_unverified(reg):
    for fid in ("IOS:SYS-5-CPUHALT", "IOS:SPANTREE-2-TOPOLOGY_CHANGE"):
        assert fid not in reg or reg[fid]["verified"] is False


def test_every_verified_example_matches_own_pattern(reg):
    bad = [i for i, e in reg.items() if e["verified"] and not compile_pattern(e).search(e["example"])]
    assert bad == []


def test_normalized_shape(reg):
    assert len(reg) > 200
    for i, e in reg.items():
        assert e["id"] == i
        assert e["header_style"] in STYLES
        assert e["severity"] is None or isinstance(e["severity"], int)
        assert isinstance(e["verified"], bool)
        if e["demoted_reason"]:
            assert e["verified"] is False
        compile_pattern(e)  # never crashes


def test_demoted_entries_keep_data(reg):
    demoted = [e for e in reg.values() if e["demoted_reason"]]
    assert demoted and all(e["verified"] is False and "message" in e for e in demoted)


def test_cpurising_empty_top_processes_matches_own_pattern(reg):
    e = reg["IOS:SYS-1-CPURISINGTHRESHOLD"]
    fields = {n: "5" for n in e["placeholders"]}
    fields["top_processes"] = ""
    assert compile_pattern(e).search(render_message(e, fields))


def test_repeated_placeholder_renamed_and_optional_dropped(reg):
    e = reg["ASA:302014"]
    assert {"interface", "interface_2"} <= set(e["placeholders"])
    fields = {n: "x" for n in e["placeholders"]} | {"idfw_user": "", "idfw_user_2": "", "initiator_interface": "", "user": "", "reason": "Unknown"}
    out = render_message(e, fields)
    assert "from " not in out and compile_pattern(e).search(out)


def test_inline_choice_becomes_named_placeholder(reg):
    e = reg["ASA:302013"]
    assert "{choice_1}" in e["message"] and e["placeholders"]["choice_1"] == "inbound|outbound"
    assert render_message({"message": "a [[ b {x}]] c {y}", "placeholders": {}}, {"y": "1"}) == "a  c 1"
