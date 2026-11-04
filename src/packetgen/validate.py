"""The validator: is this scenario spec real, consistent and fair before anything is rendered?

`validate(spec, registry)` returns findings (see findings.py). Any `error` blocks the build.
Rule ids match docs/DESIGN.md and the packet-builder skill's fix table.

Order matters: schema (S0) first, then registry (R) and time parsing (T1). Rules that need
parsed times are skipped when T1 fails, because a naive timestamp has no comparable instant.
"""
from __future__ import annotations

import re
from datetime import datetime

from packetgen.capture import capture_strings, check_capture
from packetgen.findings import finding
from packetgen.registry import compile_pattern, render_message
from packetgen.spec import schema_findings
from packetgen.ticket import check_ticket
from packetgen.timebase import parse_utc

_NAME = re.compile(r"\{(\w+)\}")
_OPTIONAL = re.compile(r"\[\[(.*?)\]\]")
_ERROR_COUNTER = re.compile(r"errors|discards|crc", re.IGNORECASE)
# Averaging windows from short to long; for one burst, a longer window can't peak higher (S3).
_CPU_WINDOWS = ("cpu_5s", "cpu_1min", "cpu_5min")


def validate(spec: dict, registry: dict[str, dict]) -> list[dict]:
    found = schema_findings(spec)
    if found:
        return found
    found = _check_registry(spec, registry)
    time_found = _check_T1(spec)
    found += time_found
    if time_found:
        return found
    dupes = _check_C5(spec)
    if dupes:
        return found + dupes  # the id maps below would silently collapse duplicates
    times = _times(spec)
    for check in (_check_T2, _check_T3, _check_T4, _check_C, _check_S):
        found += check(spec, times)
    found += _check_E(spec) + _check_K(spec) + _check_L1(spec) + _check_N1(spec)
    found += check_capture(spec)
    found += check_ticket(spec)
    found += _check_Q1(spec, registry)
    return found


# --- R: registry -------------------------------------------------------------------

def _check_registry(spec: dict, registry: dict[str, dict]) -> list[dict]:
    out = []
    devices = {d["hostname"]: d for d in spec["topology"]["devices"]}
    allow = spec["meta"]["allow_unverified"]
    for ev in spec["events"]:
        eid, fid = ev["id"], ev["format_id"]
        entry = registry.get(fid)
        if entry is None:
            out.append(finding("R1", f"{eid}: unknown format_id {fid}", "pick an id from registry/*.yaml"))
            continue
        if not entry["verified"]:
            out.append(finding("R2", f"{eid}: {fid} is unverified ({entry.get('demoted_reason') or 'source unverified'})",
                               "use a verified entry, or set meta.allow_unverified",
                               "warning" if allow else "error"))
        required = set(_NAME.findall(_OPTIONAL.sub("", entry["message"])))
        known = set(_NAME.findall(entry["message"]))
        missing = sorted(required - set(ev["fields"]))
        extra = sorted(set(ev["fields"]) - known)
        if missing:
            out.append(finding("R3", f"{eid}: missing field(s) {', '.join(missing)} for {fid}",
                               "fill every placeholder in the entry's message"))
        if extra:
            out.append(finding("R3", f"{eid}: field(s) {', '.join(extra)} not in {fid}",
                               "remove fields the message doesn't use", "warning"))
        if not missing:
            try:
                rendered = render_message(entry, ev["fields"])
            except ValueError as exc:  # an optional [[...]] section filled only partly
                out.append(finding("R3", f"{eid}: {exc} (optional sections are all-or-nothing)",
                                   "fill every field in an optional section, or none of them"))
            else:
                if not compile_pattern(entry).search(rendered):
                    out.append(finding("R4", f"{eid}: rendered {fid} doesn't match its pattern",
                                       "use values that fit each placeholder's regex"))
        device = devices.get(ev["device"])
        if device and entry["header_style"] != device["header_style"]:
            out.append(finding("R5", f"{eid}: {fid} needs header_style {entry['header_style']}, "
                                     f"{ev['device']} is {device['header_style']}",
                               "emit it from a device of that style, or pick another entry"))
    return out


# --- T: time -------------------------------------------------------------------------

def _all_timestamps(spec: dict) -> list[tuple[str, str]]:
    w = spec["meta"]["window"]
    stamps = [("meta.window.start", w["start"]), ("meta.window.end", w["end"])]
    stamps += [(e["id"], e["t"]) for e in spec["events"]]
    stamps += [(f"{s['id']} point {i}", p[0]) for s in spec["telemetry"] for i, p in enumerate(s["points"])]
    stamps += [(c["id"], c["t_change"]) for c in spec["config_diffs"]]
    cap = spec.get("capture")
    if cap:
        stamps += [("capture.start", cap["start"]), ("capture.end", cap["end"])]
        stamps += [(f["id"], f["t"]) for f in cap["flows"]]
    return stamps


def _check_T1(spec: dict) -> list[dict]:
    out = []
    for where, value in _all_timestamps(spec):
        try:
            parse_utc(value)
        except ValueError:
            out.append(finding("T1", f"{where}: {value!r} is naive or unparsable",
                               "use ISO-8601 with Z, e.g. 2025-06-01T12:00:00Z"))
    return out


def _times(spec: dict) -> dict[str, datetime]:
    """When each id happened: events and capture flows at t, diffs at t_change."""
    t = {e["id"]: parse_utc(e["t"]) for e in spec["events"]}
    t.update({c["id"]: parse_utc(c["t_change"]) for c in spec["config_diffs"]})
    t.update({f["id"]: parse_utc(f["t"]) for f in _flows(spec)})
    return t


def _flows(spec: dict) -> list[dict]:
    return spec.get("capture", {}).get("flows", [])


def _nodes(spec: dict) -> list[dict]:
    """Everything with an id, a label and a caused_by: events and capture flows."""
    return spec["events"] + _flows(spec)


def _check_T2(spec: dict, times: dict[str, datetime]) -> list[dict]:
    start, end = (parse_utc(spec["meta"]["window"][k]) for k in ("start", "end"))
    fix = "keep times inside meta.window (inclusive)"
    out = [finding("T2", f"{e['id']}: {e['t']} is outside the window", fix)
           for e in spec["events"] if not start <= times[e["id"]] <= end]
    out += [finding("T2", f"{s['id']}: point {p[0]} is outside the window", fix)
            for s in spec["telemetry"] for p in s["points"] if not start <= parse_utc(p[0]) <= end]
    out += [finding("T2", f"{c['id']}: change at {c['t_change']} is after the window ends", fix)
            for c in spec["config_diffs"] if times[c["id"]] > end]
    return out


def _check_T3(spec: dict, times: dict[str, datetime]) -> list[dict]:
    return [finding("T3", f"{e['id']} happens before its cause {e['caused_by']}",
                    "move the effect later or the cause earlier")
            for e in _nodes(spec)
            if e["caused_by"] in times and times[e["caused_by"]] > times[e["id"]]]


def _check_T4(spec: dict, times: dict[str, datetime]) -> list[dict]:
    root = spec["answer"]["root_cause_id"]
    symptoms = [times[e["id"]] for e in _nodes(spec) if e["label"] == "symptom"]
    is_diff = any(c["id"] == root for c in spec["config_diffs"])
    if is_diff and symptoms and times[root] >= min(symptoms):
        return [finding("T4", f"{root} changes at/after the first symptom",
                        "a causing change must precede the first symptom")]
    return []


# --- C: causality ----------------------------------------------------------------------

def _check_C5(spec: dict) -> list[dict]:
    """An id used twice across events, telemetry, config diffs and capture flows corrupts the key."""
    where: dict[str, list[str]] = {}
    for section, items in (("events", spec["events"]), ("telemetry", spec["telemetry"]),
                           ("config_diffs", spec["config_diffs"]), ("capture flows", _flows(spec))):
        for item in items:
            where.setdefault(item["id"], []).append(section)
    return [finding("C5", f"id {i} is used {len(s)} times ({', '.join(sorted(set(s)))})",
                    "give every event, series, diff and flow its own id")
            for i, s in where.items() if len(s) > 1]


def _check_C(spec: dict, times: dict[str, datetime]) -> list[dict]:
    out = []
    root = spec["answer"]["root_cause_id"]
    parents = {e["id"]: e["caused_by"] for e in _nodes(spec)}
    if root not in times:
        out.append(finding("C1", f"root_cause_id {root} is not an event or config diff",
                           "point root_cause_id at the causing event or diff"))
    for e in _nodes(spec):
        if e["label"] == "root_cause" and e["id"] != root:
            out.append(finding("C1", f"{e['id']} is labelled root_cause but the root is {root}",
                               "exactly one root: relabel it symptom/unrelated/noise"))
        if e["label"] in ("unrelated", "noise") and e["caused_by"] is not None:
            out.append(finding("C3", f"{e['id']} is {e['label']} but has caused_by {e['caused_by']}",
                               "unrelated and noise events have no parent"))
        if e["label"] == "symptom":
            problem = _trace_to_root(e["id"], parents, times, root)
            if problem:
                out.append(finding("C2", f"{e['id']}: {problem}", "make caused_by lead back to the root"))
    chain = spec["answer"]["chain"]
    if chain[0] != root:
        out.append(finding("C4", f"answer.chain starts at {chain[0]}, not the root {root}", "start the chain at the root"))
    if any(c not in times for c in chain):
        out.append(finding("C4", "answer.chain names an unknown id", "use event/diff ids"))
    elif any(times[a] > times[b] for a, b in zip(chain, chain[1:])):
        out.append(finding("C4", "answer.chain is not in time order", "order the chain by time"))
    return out


def _trace_to_root(eid: str, parents: dict[str, str | None], times: dict[str, datetime], root: str) -> str | None:
    """Follow caused_by upward. Returns what went wrong, or None if it reaches the root."""
    seen, current = set(), eid
    while current != root:
        if current in seen:
            return f"caused_by loops back through {current}"
        seen.add(current)
        if current not in times:
            return f"caused_by points at unknown id {current}"
        parent = parents.get(current)  # config diffs have no parent
        if parent is None:
            return f"chain stops at {current} without reaching {root}"
        current = parent
    return None


# --- S: telemetry ----------------------------------------------------------------------

def _check_S(spec: dict, times: dict[str, datetime]) -> list[dict]:
    out = []
    series = {s["id"]: s for s in spec["telemetry"]}
    for s in spec["telemetry"]:
        pts = [parse_utc(p[0]) for p in s["points"]]
        if any((b - a).total_seconds() != s["interval_s"] for a, b in zip(pts, pts[1:])):
            out.append(finding("S1", f"{s['id']}: points aren't exactly {s['interval_s']} s apart",
                               "one point per polling interval, increasing"))
        if _ERROR_COUNTER.search(s["metric"]):
            if s["kind"] not in ("rate", "delta"):
                out.append(finding("S2", f"{s['id']}: {s['metric']} must be graphed as rate or delta",
                                   "error/discard counters are per-poll deltas, never raw Counter32"))
            if any(p[1] < 0 for p in s["points"]):
                out.append(finding("S2", f"{s['id']}: negative {s['metric']} value", "rates and deltas are >= 0"))
    out += _check_S3(spec)
    for e in spec["events"]:
        sig = e["signal"]
        if sig is None:
            continue
        s = series.get(sig["series"])
        if s is None or s["device"] != e["device"]:
            out.append(finding("S4", f"{e['id']}: signal series {sig['series']} is missing or on another device",
                               "point the signal at a series from the same device"))
            continue
        near = [p[1] for p in s["points"]
                if abs((parse_utc(p[0]) - times[e["id"]]).total_seconds()) <= s["interval_s"]]
        holds = [v >= sig["value"] if sig["op"] == ">=" else v <= sig["value"] for v in near]
        if not any(holds):
            out.append(finding("S4", f"{e['id']}: {sig['series']} never {sig['op']} {sig['value']} "
                                     f"within one interval of the event",
                               "make the graph show what the log claims"))
    return out


def _check_S3(spec: dict) -> list[dict]:
    out = []
    peaks: dict[str, dict[str, float]] = {}
    for s in spec["telemetry"]:
        if s["metric"] in _CPU_WINDOWS:
            peaks.setdefault(s["device"], {})[s["metric"]] = max(p[1] for p in s["points"])
    for device, by_window in peaks.items():
        present = [w for w in _CPU_WINDOWS if w in by_window]
        for shorter, longer in zip(present, present[1:]):
            if by_window[longer] > by_window[shorter]:
                out.append(finding("S3", f"{device}: {longer} peaks at {by_window[longer]}, above {shorter} "
                                         f"({by_window[shorter]})",
                                   "a longer averaging window flattens a spike; lower its peak"))
    return out


# --- E, K, L, N, Q -------------------------------------------------------------------------

def _check_E(spec: dict) -> list[dict]:
    out = []
    devices = {d["hostname"] for d in spec["topology"]["devices"]}
    users = [(e["id"], e["device"]) for e in spec["events"]]
    users += [(c["id"], c["device"]) for c in spec["config_diffs"]]
    users += [(s["id"], s["device"]) for s in spec["telemetry"]]
    out += [finding("E1", f"{who}: device {dev} is not in topology", "add the device or fix the name")
            for who, dev in users if dev not in devices]
    declared = {d["mgmt_ip"].lower() for d in spec["topology"]["devices"]}
    for d in spec["topology"]["devices"]:
        declared |= {i[k].lower() for i in d.get("interfaces", []) for k in ("ip", "mac") if k in i}
    for ent in spec["topology"]["entities"].values():
        declared |= {v.lower() for v in ent.values()}
    for e in spec["events"]:
        for key, value in e["fields"].items():
            if key.lower().endswith(("ip", "mac")) and value.lower() not in declared:
                out.append(finding("E2", f"{e['id']}: {key}={value} isn't declared in topology",
                                   "declare it under topology.entities so every file agrees"))
    return out


def _check_K(spec: dict) -> list[dict]:
    out = []
    ids = {e["id"] for e in spec["events"]} | {c["id"] for c in spec["config_diffs"]}
    ids |= {s["id"] for s in spec["telemetry"]} | {f["id"] for f in _flows(spec)}
    rubric = spec["answer"]["rubric"]
    for item in rubric:
        out += [finding("K1", f"rubric {item['id']}: evidence {ref} doesn't exist", "cite a real event/series/diff id")
                for ref in item["evidence_refs"] if ref not in ids]
    rubric_ids = [item["id"] for item in rubric]
    out += [finding("K2", f"rubric id {rid} is used more than once", "make rubric ids unique")
            for rid in sorted({r for r in rubric_ids if rubric_ids.count(r) > 1})]
    return out


def _check_L1(spec: dict) -> list[dict]:
    visible = [("meta.id", spec["meta"]["id"]), ("meta.brief", spec["meta"]["brief"])]
    if spec["meta"]["difficulty"].get("show_diff_notes", False):
        visible += [(f"{c['id']} note", c["note"]) for c in spec["config_diffs"] if c["note"]]
    if "ticket" in spec:
        visible.append(("ticket.text", spec["ticket"]["text"]))
    visible += capture_strings(spec)
    return [finding("L1", f"{where} gives away the answer ({term!r})", "reword it so the root cause stays hidden")
            for term in spec["answer"]["root_cause_terms"]
            for where, text in visible if term.lower() in text.lower()]


def _check_N1(spec: dict) -> list[dict]:
    need = spec["meta"]["difficulty"].get("min_noise", 3)
    have = sum(e["label"] in ("unrelated", "noise") for e in _nodes(spec))
    if have < need:
        return [finding("N1", f"{have} unrelated/noise events, need {need}", "add realistic distractors")]
    return []


def _check_Q1(spec: dict, registry: dict[str, dict]) -> list[dict]:
    """Warn when the root cause is the single most severe line (lowest syslog severity number)."""
    def severity(e: dict) -> int | None:
        entry = registry.get(e["format_id"])
        return entry.get("severity") if entry else None

    events = {e["id"]: e for e in spec["events"]}
    root = events.get(spec["answer"]["root_cause_id"])
    root_sev = severity(root) if root else None
    others = [s for e in spec["events"] if e is not root and (s := severity(e)) is not None]
    if root_sev is not None and others and root_sev < min(others):
        return [finding("Q1", f"root cause {root['id'] if root else ''} is the loudest line (severity {root_sev})",
                        "real root causes are usually quieter than their symptoms", "warning")]
    return []
