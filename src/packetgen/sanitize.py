"""Sanitize gate: only documentation/private IPs and documentation MACs may appear.

Checks: Z1 non-documentation IP, Z2 non-documentation MAC, Z3 blocked binary suffix,
Z4 personal home path, Z5 local deny term (from the gitignored .sanitize-deny file).

Used on rendered packets (post-render check) and by scripts/pre-commit.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from packetgen.findings import finding

_ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",          # RFC 1918
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",       # RFC 5737
    "127.0.0.0/8", "224.0.0.0/4", "0.0.0.0/8", "255.0.0.0/8",  # loopback, multicast, masks
)]
# Not preceded by a digit/dot, not followed by more dotted digits (keeps "17.9.4" out).
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_MAC = re.compile(r"(?<![0-9a-f:.-])(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
                  r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})(?![0-9a-f:.-])", re.IGNORECASE)
# RFC 7042 doc range, STP/LLDP multicast, IPv4 multicast, broadcast, all-zero placeholder.
_ALLOWED_MAC_PREFIXES = ("00005e0053", "0180c20000", "01005e", "ffffffffffff", "000000000000")
# macOS, Linux and Windows home directories (bare, `\\`-escaped too); "~/" paths and URLs are fine.
_STOP = r"[^/\\\s`'\")\]]+"
_HOME_PATH = re.compile(
    r"(?<![\w.~-])(?:/(?:Users|home)/" + _STOP + r"|[A-Za-z]:\\{1,2}Users\\{1,2}" + _STOP + r")")


def load_denylist(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines = (ln.strip() for ln in path.read_text(encoding="utf-8").splitlines())
    return [ln for ln in lines if ln and not ln.startswith("#")]


def _ip_ok(text: str) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return True  # octet > 255: not an address, so nothing to leak
    return any(addr in net for net in _ALLOWED_NETS)


def sanitize_findings(text: str, where: str, deny: Sequence[str] = ()) -> list[dict]:
    out = []
    for m in _IPV4.finditer(text):
        if not _ip_ok(m.group()):
            out.append(finding("Z1", f"{where}: non-documentation IP {m.group()}",
                               "use RFC 5737 (192.0.2.0/24 ...) or RFC 1918 space"))
    for m in _MAC.finditer(text):
        hexes = re.sub(r"[^0-9a-f]", "", m.group().lower())
        if not hexes.startswith(_ALLOWED_MAC_PREFIXES):
            out.append(finding("Z2", f"{where}: non-documentation MAC {m.group()}",
                               "use 00:00:5e:00:53:xx (RFC 7042)"))
    for m in _HOME_PATH.finditer(text):
        out.append(finding("Z4", f"{where}: personal home path {m.group()}",
                           "use a relative path or `~/`"))
    for term in deny:  # message names the term; it only ever prints locally
        for _ in re.finditer(r"\s+".join(map(re.escape, term.split())), text, re.IGNORECASE):
            out.append(finding("Z5", f"{where}: local deny term {term!r}", "remove or genericize it"))
    return out


# Binary artifacts can't be text-scanned.
BLOCKED_SUFFIXES = (".xlsx", ".pdf", ".pcap", ".pcapng")


def file_findings(path: Path, deny: Sequence[str] = ()) -> list[dict]:
    if path.suffix.lower() in BLOCKED_SUFFIXES:
        return [finding("Z3", f"{path}: {path.suffix} files can't be scanned and are blocked",
                        "keep binary artifacts out of git; commit their text sources instead")]
    return sanitize_findings(path.read_text(errors="replace"), str(path), deny)


def main(argv: list[str]) -> int:
    deny = load_denylist(Path(".sanitize-deny"))
    found = []
    for name in argv:
        found += file_findings(Path(name), deny)
    if found:
        print(json.dumps(found, indent=2))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
