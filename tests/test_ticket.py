"""Ticket truth checks (TK1-TK5) and the ticket schema rule."""
import copy
import json
from pathlib import Path

from packetgen.registry import load_registry
from packetgen.spec import load_spec
from packetgen.ticket import check_ticket
from packetgen.validate import validate

ROOT = Path(__file__).parents[1]
REG = load_registry(ROOT / "registry")
CLEAN = load_spec(ROOT / "tests" / "fixtures" / "stp_dhcp_cascade.json")

TICKET = json.loads((ROOT / "tests" / "fixtures" / "ticket.json").read_text())
TEXT = TICKET["text"]


def spec(text: str = TEXT, **ticket) -> dict:
    s = copy.deepcopy(CLEAN)
    s["ticket"] = {**copy.deepcopy(TICKET), "text": text, **ticket}
    return s


def checks(s: dict) -> set[str]:
    return {f["check"] for f in check_ticket(s)}


def test_no_ticket_no_findings():
    assert check_ticket(copy.deepcopy(CLEAN)) == []


def test_clean_ticket_no_errors():
    assert not [f for f in check_ticket(spec()) if f["severity"] == "error"]


def test_unknown_device_flagged():
    assert "TK1" in checks(spec(TEXT + " Maybe SW9 is down?"))


def test_known_device_not_flagged():
    assert "TK1" not in checks(spec(TEXT + " Someone said ACC-SW2 is involved."))


def test_unknown_ip_flagged():
    assert "TK1" in checks(spec(TEXT + " My PC says 192.0.2.77."))


def test_entity_ip_not_flagged():
    assert "TK1" not in checks(spec(TEXT + " My PC is 10.20.20.41."))


def test_app_names_not_device_tokens():
    assert "TK1" not in checks(spec(TEXT + " Outlook and the HR share too, and outlook again."))


def test_interface_label_flagged():
    assert "TK1" in checks(spec(TEXT + " The jack says Gi1/0/48."))


def test_lowercase_interface_flagged():
    assert "TK1" in checks(spec(TEXT + " The jack label says gi1/0/48."))


def test_purchase_order_not_interface():
    assert "TK1" not in checks(spec(TEXT + " I put in PO 4521 for a new laptop."))


def test_anecdote_quoting_device_output_flagged():
    s = spec(TEXT + " I ran show ip int brief and it looked odd.")
    f = [x for x in check_ticket(s) if x["check"] == "TK2"]
    assert f and f[0]["severity"] == "error"


def test_claim_not_in_text():
    s = spec()
    s["ticket"]["misdirection"][0]["claim"] = "The printer is also broken."
    f = [x for x in check_ticket(s) if x["check"] == "TK3"]
    assert f and f[0]["severity"] == "error"


def test_tiny_claim_flagged():
    s = spec()
    s["ticket"]["misdirection"][0]["claim"] = "a"
    assert "TK3" in checks(s)


def test_claim_matches_case_and_whitespace():
    s = spec()
    s["ticket"]["misdirection"][0]["claim"] = "IT STARTED  RIGHT\nwhen everyone came back from lunch."
    assert "TK3" not in checks(s)


def test_no_misdirection_warns():
    f = [x for x in check_ticket(spec(misdirection=[])) if x["check"] == "TK4"]
    assert f and f[0]["severity"] == "warning"


def test_stem_giveaway_warns():
    s = spec(TEXT + " Someone mentioned bpdufilter and bridging loop on the access switch.")
    f = [x for x in check_ticket(s) if x["check"] == "TK5"]
    assert f and f[0]["severity"] == "warning"


def test_all_failures_reported():
    s = spec(TEXT + " SW9 said show ip int brief fine.")
    s["ticket"]["misdirection"][0]["claim"] = "Not in the text at all."
    assert {"TK1", "TK2", "TK3"} <= checks(s)


GIVEAWAY = " Someone mentioned bpdufilter and bridging loop on the access switch."


def test_clean_ticket_no_tk5():
    assert "TK5" not in checks(spec())


def test_stem_giveaway_ignores_brief_words():
    s = spec(TEXT + GIVEAWAY)
    s["meta"]["brief"] += GIVEAWAY
    assert "TK5" not in checks(s)


def test_stem_giveaway_counts_only_symptom_events():
    given = spec(TEXT + GIVEAWAY)
    next(e for e in given["events"] if e["label"] == "symptom")["fields"]["probe"] = GIVEAWAY
    assert "TK5" not in checks(given)

    not_given = spec(TEXT + GIVEAWAY)
    next(e for e in not_given["events"] if e["label"] in ("noise", "unrelated"))["fields"]["probe"] = GIVEAWAY
    assert "TK5" in checks(not_given)


def test_schema_rejects_bad_kind():
    s = spec()
    s["ticket"]["misdirection"][0]["kind"] = "lie"
    assert "S0" in {f["check"] for f in validate(s, REG)}
