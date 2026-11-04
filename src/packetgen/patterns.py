"""Fault-pattern catalog (scenarios/starter.yaml): loader and consistency check."""
from __future__ import annotations

from pathlib import Path

import yaml

from .capture_kinds import KINDS
from .findings import finding
from .timebase import STYLES

TOPICS = ("stp", "trunk", "acl", "aaa", "ntp", "ospf", "eigrp", "bgp", "fhrp", "port-security")
CERTS = ("ENCOR", "ENARSI", "none")
REQUIRED = ("id", "symptom", "root_cause", "registry_ids", "red_herrings", "topic", "cert")


def load_patterns(path: Path) -> list[dict]:
    return yaml.safe_load(path.read_text())


def check_patterns(patterns: list[dict], registry: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for i, p in enumerate(patterns):
        pid = str(p.get("id", f"#{i}"))
        for key in REQUIRED:
            if key not in p:
                out.append(finding("P6", f"pattern {pid}: missing key '{key}'", f"add '{key}'"))
        if pid in seen:
            out.append(finding("P5", f"pattern {pid}: duplicate id", "make pattern ids unique"))
        seen.add(pid)
        for key, allowed in (("topic", TOPICS), ("cert", CERTS)):
            if key not in p:
                out.append(finding("P4", f"pattern {pid}: {key} missing",
                                   f"use one of {', '.join(allowed)}"))
            elif p[key] not in allowed:
                out.append(finding("P4", f"pattern {pid}: {key} '{p[key]}' not allowed",
                                   f"use one of {', '.join(allowed)}"))
        for rid in p.get("registry_ids", []):
            e = registry.get(rid)
            if e is None:
                out.append(finding("P1", f"pattern {pid}: unknown registry id {rid}",
                                   "fix the id or add it to the registry"))
                continue
            if not e["verified"]:
                out.append(finding("P2", f"pattern {pid}: {rid} is not verified",
                                   "use a verified registry entry"))
            if e["header_style"] not in STYLES:
                out.append(finding("P3", f"pattern {pid}: {rid} header_style "
                                   f"{e['header_style']!r} unsupported",
                                   f"use an id with header_style in {', '.join(STYLES)}"))
        if "capture" in p:
            out.extend(_check_capture(pid, p["capture"]))
    return out


def _check_capture(pid: str, cap: object) -> list[dict]:
    fix = "use capture: {kinds: [...], evidence_kind: ..., evidence: ...}"
    if not isinstance(cap, dict):
        return [finding("P7", f"pattern {pid}: capture must be a mapping", fix)]
    missing = [k for k in ("kinds", "evidence_kind", "evidence") if k not in cap]
    if missing:
        return [finding("P7", f"pattern {pid}: capture missing {', '.join(missing)}", fix)]
    out: list[dict] = []
    kinds, ek, ev = cap["kinds"], cap["evidence_kind"], cap["evidence"]
    if not (isinstance(kinds, list) and kinds and all(isinstance(k, str) for k in kinds)):
        out.append(finding("P7", f"pattern {pid}: capture kinds must be a non-empty list of strings", fix))
        kinds = []
    if not isinstance(ek, str):
        out.append(finding("P7", f"pattern {pid}: capture evidence_kind must be a string", fix))
        ek = None
    if not (isinstance(ev, str) and ev.strip()):
        out.append(finding("P7", f"pattern {pid}: capture evidence must be a non-empty string", fix))
    for k in kinds:
        if k not in KINDS:
            out.append(finding("P7", f"pattern {pid}: capture kind {k!r} not in the flow catalog",
                               f"use one of {', '.join(KINDS)}"))
    if ek is None:
        pass
    elif ek not in kinds:
        out.append(finding("P7", f"pattern {pid}: evidence_kind {ek!r} is not in capture kinds",
                           "add it to kinds or change evidence_kind"))
    elif ek in KINDS and not KINDS[ek]["symptom_rule"]:
        out.append(finding("P7", f"pattern {pid}: evidence_kind {ek!r} has no symptom rule",
                           "use a kind with a symptom rule"))
    return out


def capture_hint(patterns: list[dict], pattern_id: str) -> dict | None:
    """The pattern's capture hint, or None when the pattern or the hint is absent."""
    for p in patterns:
        if p.get("id") == pattern_id:
            return p.get("capture")
    return None


def select_patterns(patterns: list[dict], topic: str | None = None, cert: str | None = None,
                    exclude: list[str] | None = None) -> list[str]:
    """Ids of matching patterns in file order."""
    skip = set(exclude or [])
    return [p["id"] for p in patterns
            if (topic is None or p["topic"] == topic)
            and (cert is None or p["cert"] == cert)
            and p["id"] not in skip]
