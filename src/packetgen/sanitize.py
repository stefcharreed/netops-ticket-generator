"""Sanitize gate: only documentation/private IPs and documentation MACs may appear.

Checks: Z1 non-documentation IP (IPv4 and IPv6), Z2 non-documentation MAC, Z3 blocked binary suffix,
Z4 personal home path, Z5 local deny term (from the gitignored .sanitize-deny file).

Used on rendered packets (post-render check) and by scripts/pre-commit.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from packetgen.findings import finding

_ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",          # RFC 1918
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",       # RFC 5737
    "127.0.0.0/8", "224.0.0.0/4", "0.0.0.0/8", "255.0.0.0/8",  # loopback, multicast, masks
)]
_ALLOWED_NETS6 = [ipaddress.ip_network(n) for n in (
    "2001:db8::/32", "3fff::/20",                 # documentation (RFC 3849, RFC 9637)
    "fe80::/10", "fc00::/7",                      # link-local, unique local (IPv6's RFC 1918)
    "ff00::/8", "::1/128", "::/128",              # multicast, loopback, unspecified
)]
# Hex groups joined by 2-7 colons, at least one hex digit, not touching more hex/colons, and not glued to a
# digit-dot (so a sentence's full stop doesn't hide an address, but "12:00:01.5" isn't split). Candidates that
# don't parse as IPv6 (MACs, clock times like 12:00:01) are dropped by _ip6_ok, so the regex can stay loose.
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?<!\d\.)(?=[0-9A-Fa-f:]*[0-9A-Fa-f])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
                   r"(?![0-9A-Fa-f:]|\.\d)")
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


def deny_path(cwd: Path = Path(".")) -> Path:
    """Where the .sanitize-deny list is: this checkout's own top level first, then the main checkout (found
    through git's common dir, so linked worktrees share it). If neither exists, the main checkout's path, so a
    missing-list error names the place the list belongs. Outside a git repo: `cwd/.sanitize-deny`."""
    try:
        out = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir"],
                             cwd=cwd, capture_output=True, text=True, check=True).stdout.split("\n")
    except (OSError, subprocess.CalledProcessError):
        return cwd / ".sanitize-deny"
    candidates = [Path(out[0]) / ".sanitize-deny", Path(out[1]).parent / ".sanitize-deny"]
    return next((c for c in candidates if c.is_file()), candidates[1])


def deny_required(cwd: Path = Path(".")) -> bool:
    """True when this clone says a deny list must exist (`git config packetgen.requireDeny true`)."""
    try:
        out = subprocess.run(["git", "config", "--type=bool", "--get", "packetgen.requireDeny"],
                             cwd=cwd, capture_output=True, text=True).stdout.strip()
    except OSError:
        return False
    return out == "true"


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


def _ip6_ok(text: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(text)
    except ValueError:
        return True  # a MAC, a clock time or another colon string: not an address
    if addr.ipv4_mapped:
        return _ip_ok(str(addr.ipv4_mapped))
    return any(addr in net for net in _ALLOWED_NETS6)


def sanitize_findings(text: str, where: str, deny: Sequence[str] = ()) -> list[dict]:
    out = []
    for m in _IPV4.finditer(text):
        if not _ip_ok(m.group()):
            out.append(finding("Z1", f"{where}: non-documentation IP {m.group()}",
                               "use RFC 5737 (192.0.2.0/24 ...) or RFC 1918 space"))
    for m in _IPV6.finditer(text):
        if not _ip6_ok(m.group()):
            out.append(finding("Z1", f"{where}: non-documentation IPv6 {m.group()}",
                               "use 2001:db8::/32 (RFC 3849), link-local or ULA space"))
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
    if path.is_symlink():  # a staged symlink's content is its target path: scan that text, never follow it
        return sanitize_findings(os.readlink(path), f"{path} (symlink target)", deny)
    if path.suffix.lower() in BLOCKED_SUFFIXES:
        return [finding("Z3", f"{path}: {path.suffix} files can't be scanned and are blocked",
                        "keep binary artifacts out of git; commit their text sources instead")]
    return sanitize_findings(path.read_text(errors="replace"), str(path), deny)


def main(argv: list[str]) -> int:
    path = deny_path()
    if not path.is_file() and deny_required():
        print(f"sanitize: {path.name} is missing but packetgen.requireDeny is set; refusing to scan without it",
              file=sys.stderr)
        return 1
    deny = load_denylist(path)
    found = []
    for name in argv:
        found += file_findings(Path(name), deny)
    if found:
        print(json.dumps(found, indent=2))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
