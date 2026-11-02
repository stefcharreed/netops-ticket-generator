"""BRIEF.md: the ask, the file list and the deliverable (fixed copy)."""
from __future__ import annotations

from pathlib import Path

DELIVERABLE = """\
Your write-up should cover:
- Fix: the change that resolves it.
- Labels: tag each log line as exactly one of root_cause, symptom, unrelated or noise.
- Cause: the single event that started the incident.
- Evidence: how that cause leads to each symptom, step by step, citing log ids, chart minutes
  and config diff lines.
- Certainty: how sure you are (low, medium or high), plus one check you would run to confirm it.
"""


def render_brief(spec: dict, artifacts: list[str], out: Path) -> None:
    files = "\n".join(f"- {a}" for a in artifacts)
    text = (f"# Incident packet {spec['meta']['id']}\n\n{spec['meta']['brief']}\n\n"
            f"## Files\n{files}\n\n## Deliverable\n{DELIVERABLE}")
    (out / "BRIEF.md").write_text(text)
