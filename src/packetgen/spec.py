"""Load a scenario spec and check it against schema/scenario.schema.json (check id S0)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from packetgen.findings import finding

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema" / "scenario.schema.json"


def load_spec(path: Path) -> dict:
    return json.loads(Path(path).read_text())


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


def schema_findings(spec: dict) -> list[dict]:
    out = []
    for err in sorted(_validator().iter_errors(spec), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(finding("S0", f"{where}: {err.message}", "edit the spec to match schema/scenario.schema.json"))
    return out
