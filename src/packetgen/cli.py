"""Command line: the only place that prints. Exit 1 when any finding is an error."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from packetgen.findings import has_errors

DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "registry"
DEFAULT_PATTERNS = Path(__file__).resolve().parents[2] / "scenarios" / "starter.yaml"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="packetgen")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check a scenario spec")
    v.add_argument("spec", type=Path)
    v.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    b = sub.add_parser("build", help="validate and render a packet")
    b.add_argument("spec", type=Path)
    b.add_argument("--out", type=Path, required=True, help="the output directory")
    b.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    b.add_argument("--force", action="store_true")
    t = sub.add_parser("patterns", help="list fault-pattern ids, optionally filtered")
    t.add_argument("--topic")
    t.add_argument("--cert")
    t.add_argument("--exclude", nargs="*", default=[], metavar="ID")
    t.add_argument("--file", type=Path, default=DEFAULT_PATTERNS)
    t.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    args = p.parse_args(argv)

    if args.cmd == "patterns":
        from packetgen.patterns import CERTS, TOPICS, check_patterns, load_patterns, select_patterns
        from packetgen.registry import load_registry
        for name, val, allowed in (("topic", args.topic, TOPICS), ("cert", args.cert, CERTS)):
            if val is not None and val not in allowed:
                print(f"invalid --{name} {val!r}; allowed: {', '.join(allowed)}", file=sys.stderr)
                return 2
        pats = load_patterns(args.file)
        bad = check_patterns(pats, load_registry(args.registry))
        if bad:
            print(json.dumps(bad, indent=2), file=sys.stderr)
            return 2
        ids = select_patterns(pats, args.topic, args.cert, args.exclude)
        print("\n".join(ids))
        return 0 if ids else 1

    if args.cmd == "validate":
        from packetgen.registry import load_registry
        from packetgen.spec import load_spec
        from packetgen.validate import validate
        findings = validate(load_spec(args.spec), load_registry(args.registry))
        print(json.dumps(findings, indent=2))
        return 1 if has_errors(findings) else 0

    from packetgen.build import build_packet  # pulls in matplotlib; keep validate fast
    result = build_packet(args.spec, args.out, args.registry, date.today(), force=args.force)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
