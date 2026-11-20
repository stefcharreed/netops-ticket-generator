"""Flow-kind catalog for the synthetic SPAN capture: param schemas, endpoint needs, filters.

Pure data plus two helpers; no dpkt. Display filters are catalog constants only,
never built from spec text. Param schemas are plain JSON Schema (draft 2020-12).
"""
from __future__ import annotations

_RETRIES = {"type": "integer", "minimum": 0}
_PERIODIC = {"stp_bpdu": (10, 2), "cdp": (1, 60), "hsrp_hello": (5, 3)}  # kind -> default (count, interval_s)

KINDS: dict[str, dict] = {
    "radius_request": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome", "username", "client", "nas_port"],
            "properties": {
                "outcome": {"enum": ["accept", "reject", "no_response"]},
                "username": {"type": "string", "pattern": "^(?!.*\n)[a-z][a-z0-9._-]{0,31}$"},
                "client": {"type": "string", "minLength": 1},
                "nas_port": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^(?!.*\n)[ -~]+$"},
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
        "symptom_rule": True,
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
                "name": {"type": "string", "pattern": "^(?!.*\n)(.*\\.)?(test|example\\.(com|net|org))$"},
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
    "stp_bpdu": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome"],
            "properties": {
                "outcome": {"enum": ["bpdu", "topology_change"]},
                "proto": {"enum": ["ieee", "pvst"], "default": "ieee"},
                "count": {"type": "integer", "minimum": 1, "maximum": 300, "default": 10},
                "interval_s": {"type": "integer", "minimum": 1, "maximum": 10, "default": 2},
            },
        },
        "needs": {"src": ("mac",), "dst": ()},
        "symptom_rule": True,
        "l2_dst": "0180c2000000",  # ieee; pvst uses 01000ccccccd. Either is l2_control.
        "filters": {"bpdu": "stp", "topology_change": "stp.flags.tc == 1"},
    },
    "cdp": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome", "native_vlan", "device_id", "port_id"],
            "properties": {
                "outcome": {"enum": ["announce"]},
                "native_vlan": {"type": "integer", "minimum": 1, "maximum": 4094},
                "device_id": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9-]{0,62}$"},
                "port_id": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^(?!.*\n)[ -~]+$"},
                "count": {"type": "integer", "minimum": 1, "maximum": 20, "default": 1},
                "interval_s": {"type": "integer", "minimum": 5, "maximum": 300, "default": 60},
            },
        },
        "needs": {"src": ("mac",), "dst": ()},
        "symptom_rule": True,
        "l2_dst": "01000ccccccc",
        "filters": {"announce": "cdp.native_vlan"},
    },
    "hsrp_hello": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome", "group", "vip"],
            "properties": {
                "outcome": {"enum": ["active", "standby", "speak"]},
                "group": {"type": "integer", "minimum": 0, "maximum": 255},
                "vip": {"type": "string", "pattern": "^(\\d{1,3}\\.){3}\\d{1,3}$"},
                "priority": {"type": "integer", "minimum": 0, "maximum": 255, "default": 100},
                "count": {"type": "integer", "minimum": 1, "maximum": 200, "default": 5},
                "interval_s": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
            },
        },
        "needs": {"src": ("mac", "ip"), "dst": ()},
        "symptom_rule": True,
        "mcast_ip": "224.0.0.2",
        "filters": {"active": "hsrp.state == 16", "standby": "hsrp.state == 8", "speak": "hsrp.state == 4"},
    },
    "dhcp": {
        "params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["outcome"],
            "properties": {
                "outcome": {"enum": ["ack", "no_offer"]},
                "retries": {**_RETRIES, "maximum": 5, "default": 3},
                "copies": {"type": "integer", "minimum": 1, "maximum": 50, "default": 1},
            },
        },
        "needs": {"src": ("mac",), "dst": ("ip",)},
        "symptom_rule": True,  # no_offer only (PK5)
        "filters": {"ack": "dhcp.option.dhcp == 5", "no_offer": "dhcp.option.dhcp == 1"},
    },
}


def span_s(flow: dict) -> float:
    """Upper bound of the last frame's offset from the flow's `t`, in seconds."""
    p = flow["params"]
    outcome = p["outcome"]
    if flow["kind"] in _PERIODIC:
        count, interval = _PERIODIC[flow["kind"]]
        return float(p.get("interval_s", interval) * (p.get("count", count) - 1))
    if flow["kind"] == "dhcp":
        replay = (p.get("copies", 1) - 1) * 0.002  # each copy lands up to 2 ms after the one before
        return (4.0 * p.get("retries", 3) + 0.01 if outcome == "no_offer" else 0.1) + replay
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
