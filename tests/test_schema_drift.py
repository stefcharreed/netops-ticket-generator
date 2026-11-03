"""Schema enums that duplicate Python constants must stay in step with them."""
import json
from pathlib import Path

from packetgen.ticket import MISDIRECTION_KINDS, PERSONAS
from packetgen.timebase import STYLES

PROPS = json.loads((Path(__file__).parents[1] / "schema" / "scenario.schema.json").read_text())["properties"]
TICKET = PROPS["ticket"]["properties"]
DEVICE = PROPS["topology"]["properties"]["devices"]["items"]["properties"]


def test_misdirection_kinds_match_schema():
    assert TICKET["misdirection"]["items"]["properties"]["kind"]["enum"] == list(MISDIRECTION_KINDS)


def test_personas_match_schema():
    assert TICKET["persona"]["enum"] == list(PERSONAS)


def test_header_styles_match_schema():
    assert DEVICE["header_style"]["enum"] == list(STYLES)
