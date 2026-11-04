"""Flow-kind catalog for the synthetic SPAN capture: param schemas, endpoint needs, filters.

Pure data plus two helpers; no dpkt. Display filters are catalog constants only,
never built from spec text. Param schemas are plain JSON Schema (draft 2020-12).
"""
from __future__ import annotations

_RETRIES = {"type": "integer", "minimum": 0}

KINDS: dict[str, dict] = {
    "radius_request": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome", "username", "client", "nas_port"],
            "properties": {
                "outcome": {"enum": ["accept", "reject", "no_response"]},
                "username": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,31}$"},
                "client": {"type": "string", "minLength": 1},
                "nas_port": {"type": "string", "minLength": 1},
                "retries": {**_RETRIES, "maximum": 10, "default": 3},
                "timeout_s": {"type": "integer", "minimum": 1, "maximum": 60, "default": 5},
                "auth_port": {"enum": [1812, 1645], "default": 1812},
            },
        },
        "needs": {"src": ("mac", "ip"), "dst": ("ip",)},
        "symptom_rule": True,
        "filters": {
            "no_response": "radius.code == 1 && !radius.rspframe",
            "accept": "radius.code == 2",
            "reject": "radius.code == 3",
        },
    },
    "arp": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome"],
            "properties": {
                "outcome": {"enum": ["reply", "no_reply", "gratuitous"]},
                "retries": {**_RETRIES, "maximum": 5, "default": 2},
            },
        },
        "needs": {"src": ("mac", "ip"), "dst": ("ip",)},
        "symptom_rule": False,
        "filters": {
            "reply": "arp.opcode == 2",
            "no_reply": "arp.opcode == 1",
            "gratuitous": "arp.isgratuitous",
        },
    },
    "dns_query": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome", "name"],
            "properties": {
                "outcome": {"enum": ["ok", "nxdomain", "servfail", "timeout"]},
                "name": {"type": "string", "pattern": r"(^|\.)(test|example\.(com|net|org))$"},
                "qtype": {"enum": ["A", "AAAA"], "default": "A"},
                "answer": {"type": "string", "minLength": 1},
                "retries": {**_RETRIES, "maximum": 5, "default": 1},
            },
            "if": {"properties": {"outcome": {"const": "ok"}}, "required": ["outcome"]},
            "then": {"required": ["answer"]},
        },
        "needs": {"src": ("mac", "ip"), "dst": ("ip",)},
        "symptom_rule": False,
        "filters": {
            "ok": "dns.flags.response == 1 && dns.flags.rcode == 0",
            "nxdomain": "dns.flags.rcode == 3",
            "servfail": "dns.flags.rcode == 2",
            "timeout": "dns.flags.response == 0 && !dns.response_in",
        },
    },
}


def span_s(flow: dict) -> float:
    """Upper bound of the last frame's offset from the flow's `t`, in seconds."""
    p = flow["params"]
    outcome = p["outcome"]
    if flow["kind"] == "radius_request":
        if outcome == "no_response":
            return float(p.get("timeout_s", 5) * p.get("retries", 3))
        return 0.05
    if flow["kind"] == "arp":
        if outcome == "no_reply":
            return 1.0 * p.get("retries", 2)
        return 0.0 if outcome == "gratuitous" else 0.01
    if outcome == "timeout":  # dns_query
        return 2.0 * p.get("retries", 1)
    return 0.05


def expected_filter(flow: dict) -> str:
    """The tshark display filter that must match this flow's frames."""
    return KINDS[flow["kind"]]["filters"][flow["params"]["outcome"]]
