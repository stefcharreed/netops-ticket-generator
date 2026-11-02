"""Normalize the source registry YAMLs (not included in this repo): python scripts/import_registry.py SRC_DIR DEST_DIR

Each source file becomes DEST_DIR/<same name> holding entries with the fields
id, vendor, header_style, severity, message, placeholders, example, source_url,
verified, demoted_reason. Entries that can't be normalized cleanly are demoted
(verified: false + demoted_reason), never dropped.
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from packetgen.registry import FREE_TEXT, compile_pattern  # noqa: E402

# id prefix -> header_style (ios, nxos, asa, bsd, meraki, None = unsupported)
HEADER_STYLE = {
    "IOS": "ios", "C9800": "ios", "NXOS": "nxos", "ASA": "asa", "FTD": "asa",
    "MERAKI": "meraki", "ISE": "bsd", "ISCDHCPD": "bsd", "JUNOS": "bsd",
    "CHRONY": "bsd", "NTPD": "bsd", "UNBOUND": "bsd",
}
_VENDOR_TOKEN = re.compile(r"%[A-Z][A-Z0-9_]*-")
_PROGRAM_TAG = re.compile(r"[A-Za-z][\w.-]*\[\{?\w+\}?(?::\{?\w+\}?)?\]:")
_LEADING_HEADER = re.compile(
    r"^(?:<\{pri\}>|\{(?:mon|day|date|ts|ctime|seq|pri|epoch_ns|device_name|hh_mm_ss\w*|time\w*|\w*host\w*)\}[:\s]*)+")
_OPTIONAL = re.compile(r"(\s?)\[((?:\(|\s|Group)[^\[\]]*)\]")  # [({user})] / [ from {x}] / [Group = {g}, ]
_BRACE = re.compile(r"\{([^{}]+)\}")
_WORDS = re.compile(r"[\w.\-/ :]+")


def _choices(text: str) -> str | None:
    """'a|b|c' of plain tokens -> escaped alternation; anything else -> None."""
    parts = [p.strip() for p in text.split("|")]
    if len(parts) < 2 or "..." in text or not all(p and _WORDS.fullmatch(p) for p in parts):
        return None
    return "|".join(re.escape(p).replace("\\ ", " ") for p in parts)


def _placeholder_regex(desc: object) -> str:
    if isinstance(desc, list):
        return "|".join(re.escape(str(x)).replace("\\ ", " ") for x in desc) or FREE_TEXT
    text = str(desc or "").strip()
    if m := re.match(r"\^(.*?)\$(?:\s|$)", text):
        try:
            re.compile(m.group(1))
            return m.group(1)
        except re.error:
            return FREE_TEXT
    return _choices(text) or FREE_TEXT


def _scrub(example: str | None) -> str | None:
    """Fix the one non-doc MAC the sanitize gate rejects (zero target MAC in an ARP log)."""
    return example.replace("0000.0000.0000", "0000.5e00.5351") if example else example


def _severity(value: object) -> int | None:
    m = re.match(r"\s*(\d+)", str(value))
    return int(m.group(1)) if m else None


def _message(entry: dict) -> str:
    """Template text from the vendor token / program tag on, with IOS/NX-OS tokens restored."""
    t = re.sub(r"^\.\.\.\s*", "", entry["template"].strip())  # leading "..." = elided header
    prefix, _, rest = entry["id"].partition(":")
    if m := _VENDOR_TOKEN.search(t):
        t = t[m.start():]
    elif prefix in ("IOS", "NXOS"):
        t = f"%{rest}: {t}"
    elif m := _PROGRAM_TAG.search(t):
        t = t[m.start():]
    else:
        t = _LEADING_HEADER.sub("", t)
    return re.sub(r"[,\s]*\.\.\.\s*$", "", t)  # trailing "..." = truncated; patterns are unanchored


def _normalize_names(message: str, described: dict) -> tuple[str, dict[str, str]]:
    """Unique valid placeholder names; inline {A|B} -> choice_N; [..] optional -> [[..]]."""
    message = _OPTIONAL.sub(lambda m: f"[[{m.group(1)}{m.group(2)}]]", message)
    seen: collections.Counter = collections.Counter()
    regexes: dict[str, str] = {}
    choices = 0

    def name_for(m: re.Match) -> str:
        nonlocal choices
        raw = m.group(1).strip()
        if "|" in raw:
            choices += 1
            name, rx = f"choice_{choices}", _choices(raw) or FREE_TEXT
        else:
            base = re.sub(r"\W+", "_", raw).strip("_") or "field"
            seen[base] += 1
            name = base if seen[base] == 1 else f"{base}_{seen[base]}"
            rx = _placeholder_regex(described.get(raw, described.get(base)))
        regexes[name] = rx
        return "{" + name + "}"

    return _BRACE.sub(name_for, message), regexes


def normalize(entry: dict) -> dict:
    prefix = entry["id"].partition(":")[0]
    out = {
        "id": entry["id"], "vendor": entry.get("vendor"), "header_style": HEADER_STYLE.get(prefix),
        "severity": _severity(entry.get("severity")), "message": "", "placeholders": {},
        "example": _scrub(entry.get("example")), "source_url": entry.get("source_url"),
        "verified": entry.get("verified") is True, "demoted_reason": None,
    }
    reason = None
    if not entry.get("template"):
        reason = "no template in source"
    else:
        raw = entry.get("placeholders")
        out["message"], out["placeholders"] = _normalize_names(
            _message(entry), raw if isinstance(raw, dict) else {})
        if out["verified"]:
            try:
                if not out["example"]:
                    reason = "no example to check"
                elif not compile_pattern(out).search(out["example"]):
                    reason = "example does not match its own pattern"
            except re.error as exc:
                reason = f"pattern does not compile: {exc}"
    if reason and out["verified"]:
        out["verified"], out["demoted_reason"] = False, reason
    return out


def import_registry(src: Path, dest: Path) -> dict[str, list[dict]]:
    dest.mkdir(parents=True, exist_ok=True)
    result = {}
    for path in sorted(src.glob("*.yaml")):
        entries = [normalize(e) for e in yaml.safe_load(path.read_text())]
        (dest / path.name).write_text(
            "# Normalized from the source registry YAMLs (not included in this repo) by scripts/import_registry.py. "
            "Edit with care; keep fields as documented in registry/README.md.\n"
            + yaml.safe_dump(entries, sort_keys=False, width=10_000, allow_unicode=True))
        result[path.name] = entries
    return result


if __name__ == "__main__":
    result = import_registry(Path(sys.argv[1]).expanduser(), Path(sys.argv[2]))
    reasons: collections.Counter = collections.Counter()
    prefixes: collections.Counter = collections.Counter()
    for name, entries in result.items():
        ok = sum(e["verified"] for e in entries)
        demoted = [e for e in entries if e["demoted_reason"]]
        print(f"{name}: {len(entries)} entries, {ok} verified, {len(demoted)} demoted")
        reasons.update(e["demoted_reason"] for e in demoted)
        prefixes.update((e["id"].partition(":")[0], e["header_style"]) for e in entries)
    print("demotion reasons:", dict(reasons))
    print("prefix -> header_style:", {p: s for (p, s) in sorted(prefixes, key=str)})
