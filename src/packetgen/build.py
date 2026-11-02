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


def build_packet(spec_path: Path, out_root: Path, registry_dir: Path, today: date,
                 force: bool = False) -> dict:
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
    spec_path.with_suffix(".manifest.json").write_text(json.dumps({"packet_dir": str(dest), **manifest}, indent=2))
    return _result(True, dest, findings, manifest)
