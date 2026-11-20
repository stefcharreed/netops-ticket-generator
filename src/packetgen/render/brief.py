"""BRIEF.md: the ask, the file list and the deliverable (fixed copy)."""
from __future__ import annotations

from pathlib import Path

from packetgen.capture_views import method_label
from packetgen.timebase import parse_utc

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
    cap = spec.get("capture")
    deliverable, section = DELIVERABLE, ""
    if cap:
        deliverable = deliverable.replace("minutes\n  and config diff lines.",
                                          "minutes,\n  config diff lines and capture frame numbers.")
        lo, hi = (parse_utc(cap[k]).strftime("%H:%M") for k in ("start", "end"))
        toward = f" (toward {cap['peer']})" if cap.get("peer") else ""
        section = (f"## Capture\n{method_label(cap)} on {cap['device']} {cap['interface']}{toward}, "
                   f"both directions, {lo}–{hi} UTC.\n{cap['reason']}\n\n")
    text = (f"# Incident packet {spec['meta']['id']}\n\n{spec['meta']['brief']}\n\n"
            f"## Files\n{files}\n\n{section}## Deliverable\n{deliverable}")
    (out / "BRIEF.md").write_text(text)
