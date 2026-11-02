"""config_diffs.txt: unified diffs of recent changes, notes hidden unless the difficulty knob shows them."""
from __future__ import annotations

import difflib
from pathlib import Path

from packetgen.timebase import parse_utc


def render_configs(spec: dict, out: Path) -> dict[str, int]:
    if not spec["config_diffs"]:
        return {}
    out.mkdir(parents=True, exist_ok=True)
    show_notes = spec["meta"]["difficulty"].get("show_diff_notes", False)
    lines: list[str] = []
    manifest = {}
    for cd in sorted(spec["config_diffs"], key=lambda c: parse_utc(c["t_change"])):
        manifest[cd["id"]] = len(lines) + 1
        name = f"{cd['device']}/{cd['id']}"
        before, after = cd["before"].splitlines(), cd["after"].splitlines()
        # Full context: a stanza's header line (e.g. "interface Gi1/0/48") says which port changed.
        lines += difflib.unified_diff(before, after, fromfile=f"a/{name}", tofile=f"b/{name}",
                                      n=max(len(before), len(after)), lineterm="")
        if show_notes and cd["note"]:
            lines.append(f"! NOTE: {cd['note']}")
        lines.append("")
    (out / "config_diffs.txt").write_text("\n".join(lines))
    return manifest
