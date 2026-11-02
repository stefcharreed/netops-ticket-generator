"""Normalized log-format registry: load, compile a message to a regex, render a message.

A normalized message uses `{name}` placeholders and `[[ ... ]]` optional sections.
`placeholders` maps each name to a regex string; a missing/empty regex means free text (`.*?`).
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_TOKEN = re.compile(r"\[\[(.*?)\]\]|\{(\w+)\}")
_NAME = re.compile(r"\{(\w+)\}")
_OPTIONAL = re.compile(r"\[\[(.*?)\]\]")
FREE_TEXT = ".*?"


def load_registry(dir: Path) -> dict[str, dict]:
    """Read every *.yaml in `dir` into {id: entry}; duplicate ids are an error."""
    out: dict[str, dict] = {}
    for path in sorted(Path(dir).glob("*.yaml")):
        for entry in yaml.safe_load(path.read_text()):
            if entry["id"] in out:
                raise ValueError(f"duplicate registry id {entry['id']} in {path.name}")
            out[entry["id"]] = entry
    return out


def _literal(text: str) -> str:
    """Escape literal text; any whitespace run matches any whitespace run."""
    return r"\s+".join(re.escape(w) for w in re.split(r"\s+", text))


def _regex(text: str, placeholders: dict[str, str]) -> str:
    out, pos = [], 0
    for m in _TOKEN.finditer(text):
        out.append(_literal(text[pos:m.start()]))
        if m.group(2):
            name = m.group(2)
            out.append(f"(?P<{name}>{placeholders.get(name) or FREE_TEXT})")
        else:
            out.append(f"(?:{_regex(m.group(1), placeholders)})?")
        pos = m.end()
    out.append(_literal(text[pos:]))
    return "".join(out)


def compile_pattern(entry: dict) -> re.Pattern:
    """Unanchored pattern for the entry's message; use .search() on a full log line."""
    return re.compile(_regex(entry["message"], entry.get("placeholders", {})))


def render_message(entry: dict, fields: dict[str, str]) -> str:
    """Fill the message. Optional sections drop when all their fields are missing/empty."""
    def optional(m: re.Match) -> str:
        names = _NAME.findall(m.group(1))
        return fill(m.group(1)) if any(fields.get(n) for n in names) else ""

    def fill(text: str) -> str:
        missing = [n for n in _NAME.findall(text) if n not in fields]
        if missing:
            raise ValueError(f"{entry.get('id', 'entry')}: missing placeholder(s) {', '.join(missing)}")
        return _NAME.sub(lambda m: str(fields[m.group(1)]), text)

    return fill(_OPTIONAL.sub(optional, entry["message"]))
