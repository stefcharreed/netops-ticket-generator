"""Truth checks for the end-user trouble ticket: personas, misdirection kinds and checks TK1-TK5.

Seam discipline: returns plain findings, never prints.
Misleading is not lying: every planted claim is true of the scenario; the five
misdirection kinds are the only permitted ways to point it the wrong way.
"""
from __future__ import annotations

import re

from packetgen.findings import finding

#: The five ways a ticket may mislead. Each is a TRUE statement pointed the wrong way.
MISDIRECTION_KINDS = ("misattribution", "scope", "coincidence", "omission", "stale")

PERSONAS: dict[str, dict] = {
    "end_user": {
        "ability": "none",
        "role": "end user",
        "evidence": "anecdote",
        "confidence": "hedging",
        "voice": ("a non-technical employee reporting what they noticed. They "
                  "describe an application or a share, never a device, protocol "
                  "or interface, and they hedge rather than diagnose."),
    },
}

#: Evidence an `anecdote` reporter cannot possibly have.
_DEVICE_EVIDENCE = re.compile(
    r"\bshow\s+(?:ip|ipv6|interface|interfaces|run|running|cdp|lldp|version|vlan|"
    r"spanning|standby|access|mac|route|ospf|bgp)\b|\btraceroute\b|"
    r"#\s*show\b|\bconfig\s+t\b", re.IGNORECASE)

#: A device name as a human would type it into a ticket: EDGE1, DIST2, SW-L3.
#: Mixed-case words ("Area 0", "Teams") deliberately do not match.
_DEVICE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9-]{1,}\d\b")
_ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_INTERFACE = re.compile(
    r"\b(?:Gi|Fa|Te|Tw|Hu|Po|Vl|GigabitEthernet|FastEthernet|TenGigabitEthernet|"
    r"Port-channel|Vlan)\s?\d[\d/.]*\b"
    # Lowercase too, but only in slot/port form, so prose like "PO 4521" is not an interface.
    r"|(?i:\b(?:gi|fa|te|tw|hu|gigabitethernet|fastethernet|tengigabitethernet)\s?\d+/[\d/.]*\d\b)")

#: A planted claim shorter than this is too thin to mislead anyone (and matches by accident).
_MIN_CLAIM_WORDS = 4

#: Shared stems with the fault before a ticket has given the answer away (a WARNING).
_GIVEAWAY_TERMS = 2

_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset("""
the and are was were that this with from for its it you your when then than
which what have has had been being into onto only also any all one two does
did will can because there their they them some such not but does after
""".split())
_STEM = 4


def _stems(text: str) -> set[str]:
    return {w[:_STEM] for w in _WORD.findall((text or "").lower())
            if len(w) >= 3 and w not in _STOPWORDS}


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def _given_stems(spec: dict) -> set[str]:
    """Stems the candidate is already handed (brief + symptom log fields); sharing them leaks nothing."""
    parts = [spec["meta"]["brief"]]
    parts += [v for e in spec["events"] if e["label"] == "symptom" for v in e["fields"].values()]
    return _stems(" ".join(parts))


def check_ticket(spec: dict) -> list[dict]:
    if "ticket" not in spec:
        return []
    ticket = spec["ticket"]
    text = ticket["text"]
    out: list[dict] = []

    topo = spec["topology"]
    names = {d["hostname"] for d in topo["devices"]}
    addrs = {d["mgmt_ip"] for d in topo["devices"]}
    addrs |= {e["ip"] for e in topo["entities"].values() if "ip" in e}

    unknown = [t for t in dict.fromkeys(_DEVICE_TOKEN.findall(text)) if t not in names]
    unknown += [a for a in dict.fromkeys(_ADDRESS.findall(text)) if a not in addrs]
    unknown += list(dict.fromkeys(_INTERFACE.findall(text)))
    for tok in unknown:
        out.append(finding(
            "TK1", f"ticket names {tok!r}, which is not a device or address in this scenario",
            "remove it, or use a hostname/address from topology; an end user should not name interfaces"))

    persona = PERSONAS.get(ticket["persona"], {})
    if persona.get("evidence") == "anecdote" and _DEVICE_EVIDENCE.search(text):
        out.append(finding(
            "TK2", "an anecdote-only persona quotes device output",
            "rewrite as what the user saw (apps, shares, timing), not commands"))

    ntext = _norm(text)
    for m in ticket["misdirection"]:
        if len(m["claim"].split()) < _MIN_CLAIM_WORDS:
            out.append(finding(
                "TK3", f"misdirection claim {m['claim']!r} is under {_MIN_CLAIM_WORDS} words",
                "plant a full sentence the user would actually write"))
        elif _norm(m["claim"]) not in ntext:
            out.append(finding(
                "TK3", f"misdirection claim {m['claim']!r} does not appear in the ticket text",
                "copy the claim from the ticket text, or add it to the text"))

    if not ticket["misdirection"]:
        out.append(finding(
            "TK4", "ticket plants no misdirection", "add at least one true-but-misleading claim",
            severity="warning"))

    ans = spec["answer"]
    fault = ans["fix"] + " " + " ".join(ans["root_cause_terms"])
    shared = (_stems(text) & _stems(fault)) - _given_stems(spec)
    if len(shared) >= _GIVEAWAY_TERMS:
        out.append(finding(
            "TK5", f"ticket shares {len(shared)} word stems with the fault ({sorted(shared)})",
            "reword the symptom in the user's own terms", severity="warning"))
    return out
