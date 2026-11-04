"""tshark read-back of the synthetic capture: the independent check that real dissectors agree.

Seam discipline: returns plain data, never prints. Display filters come only from
catalog constants (capture_kinds), never from spec text.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

MIN_VERSION = (4, 2)
BAD_FRAME_FILTER = "_ws.malformed || _ws.expert.severity == error"
_TIMEOUT_S = 120  # ceiling: a 5,000-frame capture reads back in well under a second


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    # TZ keeps local-time "Arrival Time" lines out of the dump; an empty WIRESHARK_CONFIG_DIR keeps a personal
    # profile (disabled protocols, preferences, colour rules) from changing the dissection.
    with tempfile.TemporaryDirectory(prefix="packetgen-wscfg-") as cfg:
        env = {**os.environ, "TZ": "UTC", "WIRESHARK_CONFIG_DIR": cfg}
        return subprocess.run(["tshark", *args], capture_output=True, text=True, env=env,
                              timeout=_TIMEOUT_S, check=False)


def tshark_version() -> tuple[int, int, int] | None:
    """(major, minor, patch) from `tshark --version`, or None when absent or unparsable."""
    try:
        proc = _run(["--version"])
    except (OSError, subprocess.SubprocessError):
        return None
    first = proc.stdout.splitlines()[0] if proc.stdout else ""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", first)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def _frame_numbers(pcap: Path, display_filter: str | None) -> tuple[list[int], str | None]:
    """Frame numbers matching the filter, or ([], stderr) when tshark rejects it."""
    args = ["-2", "-n", "-r", str(pcap)]
    if display_filter:
        args += ["-Y", display_filter]
    proc = _run([*args, "-T", "fields", "-e", "frame.number"])
    if proc.returncode != 0:
        return [], (proc.stderr.strip() or f"tshark exited {proc.returncode}")
    return [int(x) for x in proc.stdout.split()], None


def read_back(pcap: Path, filters: dict[str, str]) -> dict:
    """Two-pass read of `pcap`: frame count, bad frames, per-key filter matches, and the -V dump."""
    try:
        return _read_back(pcap, filters)
    except (OSError, subprocess.SubprocessError) as e:  # tshark vanished or hung: report, never raise
        return {"frames": 0, "bad_frames": [], "matches": {}, "dump": "",
                "filter_errors": {"tshark": f"{type(e).__name__}: {e}"}}


def _read_back(pcap: Path, filters: dict[str, str]) -> dict:
    frames, err = _frame_numbers(pcap, None)
    filter_errors: dict[str, str] = {}
    if err:
        filter_errors["_frames"] = err
    bad, err = _frame_numbers(pcap, BAD_FRAME_FILTER)
    if err:
        filter_errors["_bad_frames"] = err
    matches: dict[str, list[int]] = {}
    for key, flt in filters.items():
        matches[key], err = _frame_numbers(pcap, flt)
        if err:
            filter_errors[key] = err
    proc = _run(["-2", "-n", "-r", str(pcap), "-V"])
    dump = proc.stdout
    if proc.returncode != 0 or (frames and not dump.strip()):  # an empty dump would pass the sanitize gate vacuously
        filter_errors["_dump"] = proc.stderr.strip() or f"-V dump failed or was empty (exit {proc.returncode})"
    return {"frames": len(frames), "bad_frames": bad, "matches": matches,
            "filter_errors": filter_errors, "dump": dump}
