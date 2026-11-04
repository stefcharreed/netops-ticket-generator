"""validate -> render into a temp dir -> post-render checks -> atomic move into the output directory.

Nothing lands in the packet folder unless every check passes, and an existing
packet is never overwritten without force: it may hold GRADE.md.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import date
from pathlib import Path

import openpyxl
from openpyxl.cell.cell import Cell

from packetgen import capture_kinds, tshark
from packetgen.capture import capture_filename, capture_text
from packetgen.findings import finding, has_errors
from packetgen.registry import load_registry
from packetgen.render.brief import render_brief
from packetgen.render.configs import render_configs
from packetgen.render.logs import render_logs
from packetgen.render.telemetry import render_telemetry
from packetgen.render.ticket import render_ticket
from packetgen.sanitize import sanitize_findings
from packetgen.spec import load_spec
from packetgen.validate import validate


def _result(ok: bool, packet_dir: Path | None, findings: list[dict], manifest: dict) -> dict:
    return {"ok": ok, "packet_dir": str(packet_dir) if packet_dir else None,
            "findings": findings, "manifest": manifest}


def _postchecks(spec: dict, tmp: Path, manifest: dict) -> list[dict]:
    out = []
    rendered = {ref for part in manifest.values() for ref in part}
    for item in spec["answer"]["rubric"]:
        for ref in item["evidence_refs"]:
            if ref not in rendered:
                out.append(finding("K3", f"rubric {item['id']}: {ref} is not in any rendered file",
                                   "reference an event, series or diff that the packet actually shows"))
    ws = openpyxl.load_workbook(tmp / "logs.xlsx").active
    assert ws is not None
    for r in range(2, ws.max_row + 1):
        cell = ws.cell(row=r, column=2)
        if not (isinstance(cell, Cell) and cell.is_date):
            out.append(finding("X1", f"logs.xlsx row {r}: received_utc is not a date cell",
                               "write datetime objects, not floats or strings"))
        out += sanitize_findings(str(ws.cell(row=r, column=4).value), f"logs.xlsx row {r}")
    for name in ("config_diffs.txt", "TICKET.md", "BRIEF.md"):
        if (tmp / name).exists():
            out += sanitize_findings((tmp / name).read_text(), name)
    return out


MAX_CAPTURE_FRAMES = 5000


def _capture_checks(spec: dict, tmp: Path, manifest: dict, use_tshark: bool) -> tuple[list[dict], bool]:
    """Render the capture into tmp, add its pk map to manifest, run PK0/PK6/PK7. -> (findings, tshark_ran)."""
    try:
        from packetgen.render.capture import frame_count, render_capture  # optional extra; keep it lazy
    except ImportError:
        return [finding("PK0", "the capture extra (dpkt) is not installed", "pip install -e '.[capture]'")], False
    name = capture_filename(spec)
    manifest[name] = render_capture(spec, tmp)
    pcap = tmp / name
    count = frame_count(pcap)
    if count > MAX_CAPTURE_FRAMES:
        return [finding("PK7", f"{name}: {count} frames exceeds the {MAX_CAPTURE_FRAMES} cap",
                        "shorten capture.start..end or lower capture.noise")], False
    if not use_tshark:
        return [finding("PK6", f"{name}: the tshark read-back was skipped (--no-tshark); the capture's addresses "
                               "were still checked, its dissection was not",
                        "run without --no-tshark before handing the packet out", "warning")], False
    ver = tshark.tshark_version()
    need = ".".join(map(str, tshark.MIN_VERSION))
    if ver is None or ver[:2] < tshark.MIN_VERSION:
        have = "not found" if ver is None else ".".join(map(str, ver))
        return [finding("PK6", f"tshark {have}: read-back needs tshark >= {need}",
                        f"install Wireshark/tshark {need}+, or build with --no-tshark")], False
    symptoms = {fl["id"]: fl for fl in spec["capture"]["flows"] if fl["label"] == "symptom"}
    rb = tshark.read_back(pcap, {fid: capture_kinds.expected_filter(fl) for fid, fl in symptoms.items()})
    out = [finding("PK6", f"{name}: filter {k}: {msg}", "fix the catalog display filter")
           for k, msg in rb["filter_errors"].items()]
    if rb["bad_frames"]:
        out.append(finding("PK6", f"{name}: tshark flags malformed frames {rb['bad_frames'][:10]}",
                           "fix the frame builder for that kind"))
    if rb["frames"] != count:
        out.append(finding("PK6", f"{name}: tshark read {rb['frames']} frames, the renderer wrote {count}",
                           "the pcap is truncated or unreadable"))
    for fid in symptoms:
        if not set(rb["matches"].get(fid, [])) & set(manifest[name].get(fid, [])):
            out.append(finding("PK6", f"{name}: {fid}: tshark finds no frame matching its expected filter",
                               "the dissected capture does not show this symptom; check the flow params"))
    return out + sanitize_findings(rb["dump"], f"{name} (tshark -V)"), True


def build_packet(spec_path: Path, out_root: Path, registry_dir: Path, today: date,
                 force: bool = False, use_tshark: bool = True) -> dict:
    spec = load_spec(spec_path)
    findings = validate(spec, load_registry(registry_dir))
    if has_errors(findings):
        return _result(False, None, findings, {})
    dest = out_root / f"{today:%Y-%m-%d}-{spec['meta']['id']}"
    # Any earlier day's folder for this id counts: one packet id, one folder, one key.
    existing = [p for p in sorted(out_root.glob(f"*-{spec['meta']['id']}")) if p.is_dir()] if out_root.exists() else []
    if existing and not force:
        findings.append(finding("B1", f"{existing[0].name} already exists",
                                "pass force=True to rebuild (replaces the folder and its GRADE.md)"))
        return _result(False, None, findings, {})
    out_root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(dir=out_root, prefix=".build-"))
    try:
        manifest = {"logs.xlsx": render_logs(spec, load_registry(registry_dir), tmp),
                    "telemetry": render_telemetry(spec, tmp),
                    "config_diffs.txt": render_configs(spec, tmp),
                    "TICKET.md": render_ticket(spec, tmp)}
        tshark_ran = False
        if spec.get("capture"):
            cap_findings, tshark_ran = _capture_checks(spec, tmp, manifest, use_tshark)
            if any(f["check"] == "PK0" for f in cap_findings):  # environment error: nothing else is meaningful
                shutil.rmtree(tmp)
                return _result(False, None, cap_findings, {})
            findings += cap_findings + sanitize_findings(capture_text(spec), capture_filename(spec))
        render_brief(spec, sorted(p.name for p in tmp.iterdir()), tmp)
        findings += _postchecks(spec, tmp, manifest)
        if has_errors(findings):
            shutil.rmtree(tmp)
            return _result(False, None, findings, manifest)
        for old in existing:
            shutil.rmtree(old)
        os.replace(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    # The grader finds the packet folder from here, so "grade pkt-…" never has to guess the date.
    extra = {"tshark_checked": tshark_ran} if spec.get("capture") else {}
    spec_path.with_suffix(".manifest.json").write_text(
        json.dumps({"packet_dir": str(dest), **manifest, **extra}, indent=2))
    return _result(True, dest, findings, manifest)
