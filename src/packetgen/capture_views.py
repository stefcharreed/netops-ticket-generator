"""Per-method capture view rules: what each capture method can see, and how its frames are wrapped.

Pure data and stdlib helpers; no dpkt, so validate() can use the same rules the renderer does.
"""
from __future__ import annotations

import ipaddress

METHODS = ("span", "erspan")  # phase 3 adds epc and asa_capture
ENCAPS = ("native", "replicate")

# STP (IEEE), CDP/VTP/DTP/PAgP, and PVST+ SSTP destinations: never on a native SPAN.
L2_CONTROL_MACS = frozenset(bytes.fromhex(m) for m in ("0180c2000000", "01000ccccccc", "01000ccccccd"))
_LINK_LOCAL = ipaddress.ip_network("224.0.0.0/24")
_KEEPS = {
    ("span", "native"): {"data", "control_plane"},
    ("span", "replicate"): {"data", "control_plane", "l2_control"},
    ("erspan", None): {"data", "control_plane"},  # assumed like a native SPAN (not in Cisco's docs)
}


def _mode(cap: dict) -> tuple[str, str | None]:
    return (cap["method"], cap["span"]["encapsulation"]) if cap["method"] == "span" else (cap["method"], None)


def _native(cap: dict) -> int:
    return cap.get("span", {}).get("native_vlan", 1)


def frame_class(dst_mac: bytes) -> str | None:
    """'l2_control' for a control-protocol destination MAC, else None."""
    return "l2_control" if dst_mac in L2_CONTROL_MACS else None


def flow_class(spec: dict, flow: dict) -> str:
    """'control_plane' when the capture device sends or is sent the flow (or it is link-local multicast), else 'data'."""
    from packetgen.capture import resolve_endpoint  # capture.py imports this module
    from packetgen.capture_kinds import KINDS
    kind = KINDS.get(flow["kind"], {})
    if "l2_dst" in kind:  # a control protocol: classify by its destination MAC, as the noise frames are
        return frame_class(bytes.fromhex(kind["l2_dst"])) or "data"
    if "mcast_ip" in kind:
        return "control_plane"
    dev = spec["capture"]["device"]
    if any(flow[r] == dev or flow[r].startswith(dev + ":") for r in ("src", "dst")):
        return "control_plane"
    dst = resolve_endpoint(spec, flow["dst"])
    if dst and dst["ip"]:
        try:
            if ipaddress.IPv4Address(dst["ip"]) in _LINK_LOCAL:
                return "control_plane"
        except ValueError:
            pass  # PK3 reports bad addresses
    return "data"


def keeps(cap: dict, fclass: str) -> bool:
    """Whether this capture method can see a frame of this class."""
    return fclass in _KEEPS[_mode(cap)]


def flow_vlan(spec: dict, flow: dict) -> int:
    """flow.vlan, else the src endpoint's VLAN, else the native VLAN (1 outside a SPAN)."""
    from packetgen.capture import resolve_endpoint
    if flow.get("kind") == "cdp":
        return 1  # CDP rides VLAN 1 (tagged when the sender's native VLAN isn't 1)
    if "vlan" in flow:
        return flow["vlan"]
    src = resolve_endpoint(spec, flow["src"])
    return (src or {}).get("vlan") or _native(spec["capture"])


def sender_native(spec: dict, flow: dict) -> int:
    """The native VLAN of the trunk side that sent the flow: the far end's (as its diffs set it) or the near end's."""
    from packetgen.capture import peer_native_vlan
    from packetgen.timebase import parse_utc
    cap = spec["capture"]
    if flow["src"].partition(":")[0] == cap.get("peer"):
        return peer_native_vlan(spec, parse_utc(flow["t"])) or _native(cap)
    return _native(cap)


def tagged(cap: dict, vlan: int, native: int | None = None) -> bool:
    """True when the frame leaves the capture with an 802.1Q tag (native: the sender's native VLAN)."""
    return _mode(cap) == ("span", "replicate") and vlan != (_native(cap) if native is None else native)


def filter_suffix(spec: dict, flow: dict) -> str:
    """Constant display-filter suffix proving the encapsulation (never built from spec text)."""
    cap = spec["capture"]
    if cap["method"] == "erspan":
        return " && erspan"
    return " && vlan" if tagged(cap, flow_vlan(spec, flow), sender_native(spec, flow)) else ""


def method_label(cap: dict) -> str:
    """The BRIEF label for the capture method."""
    if cap["method"] == "erspan":
        return f"ERSPAN to {cap['erspan']['analyzer']}"
    return "Local SPAN (encapsulation replicate)" if cap["span"]["encapsulation"] == "replicate" else "Local SPAN"
