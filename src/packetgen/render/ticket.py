"""TICKET.md: what the user reported. Misdirection metadata is answer material and never rendered."""
from __future__ import annotations

from pathlib import Path

from packetgen.ticket import PERSONAS


def render_ticket(spec: dict, out: Path) -> dict[str, str]:
    ticket = spec.get("ticket")
    if not ticket:
        return {}
    role = PERSONAS[ticket["persona"]]["role"]
    (out / "TICKET.md").write_text(
        f"# Ticket TKT-{spec['meta']['id']}\n\n**Reported by:** {role}\n\n{ticket['text']}\n")
    return {"ticket": "TICKET.md"}
