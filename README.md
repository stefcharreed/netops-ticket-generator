# netops-ticket-generator

Generates realistic network-incident practice packets (syslog spreadsheet, telemetry graphs, config
diffs, an end-user ticket) for network engineer / NOC / Tier 3 troubleshooting practice, each with a
hidden, validated answer key and rubric grading.

A Claude Code skill writes each scenario as a labeled incident record (root cause / symptom /
unrelated / noise, with causal links). Python validates it against real vendor log formats and
cross-file consistency rules, then renders the files. Nothing is written unless every check passes.
Current scenarios target CCNP Enterprise (ENCOR-level) topics; the log registry is multi-vendor.

## What is and is not verified
- Fixture-tested: 273 tests.
- Live generation runs were built and leak-checked (no answer text in the packet).
- Generated packets have not yet been graded against real attempts.
- Captures: synthetic, protocol-checked and tshark-checked; not gear-validated. Only symptom flows are
  checked against their expected display filter; every frame is checked for malformed and expert errors.
- Gear-validated: none. Nothing here has been checked against real devices.
- Log formats come from a registry checked against vendor documentation, upstream source code and
  parser fixtures. Each entry has a source URL and a `verified` flag.

## Requirements
- Python 3.10 or newer
- Claude Code, for the skills (the CLI works without it)
- Optional, for packets with a synthetic SPAN capture: the `capture` extra (dpkt) and tshark 4.2 or newer
  (Homebrew `wireshark`, apt `tshark`)

## Install
```bash
python3 -m venv .venv        # must be Python 3.10+
.venv/bin/pip install -e '.[dev]'
.venv/bin/pip install -e '.[capture]'   # optional: capture packets (needs tshark >= 4.2)
```

## Use the skills
Link each skill directory into your Claude Code skills folder:
```bash
mkdir -p ~/.claude/skills
for d in skills/*/; do ln -s "$PWD/$d" ~/.claude/skills/"$(basename "$d")"; done
```
Create `~/.config/claude-skills/profile.md` with the checkout path and where packets should go:
```
packetgen_repo: ~/src/netops-ticket-generator
interview_prep_dir: ~/notes/interview-prep
```
Then ask Claude "give me a scenario". Later, answer with your diagnosis and say "grade pkt-..."
with the packet id. Answer keys are stored under `<interview_prep_dir>/Keys/` and are not shown
before grading.

## CLI
```bash
.venv/bin/python -m packetgen validate SPEC.json
.venv/bin/python -m packetgen build SPEC.json --out OUT_DIR [--force] [--no-tshark]
.venv/bin/python -m packetgen patterns [--topic T] [--cert C] [--exclude ID ...] [--show-capture ID]
```
`validate` checks a scenario spec, `build` validates and renders a packet into `OUT_DIR`
(`--no-tshark` skips the capture read-back and warns), and `patterns` lists fault-pattern ids
(`--show-capture` prints a pattern's capture hint). Run `--help` on any subcommand for options.

## Develop
```bash
.venv/bin/python -m pytest -q
.venv/bin/pyright
git config core.hooksPath scripts   # pre-commit sanitize gate
```
The gate rejects real-looking IPs, MACs, home paths, your own deny terms, and binary files (xlsx/pdf/pcap). To also block your own terms, put
one per line in a gitignored `.sanitize-deny` file at the repo root.

The first `.venv/bin/pyright` run downloads Node and needs network access.

## Known gaps
No verified VRRP or IOS NAT log ids yet; PAN-OS ids are verified but not renderable (header style
unsupported). Capture flow kinds are `radius_request`, `arp` and `dns_query` only; no VLAN-tagged
captures; AAAA answers are unsupported. Gear-validated: none.

## Docs
- [Design](docs/DESIGN.md)
- [Threat model](THREAT-MODEL.md)

## License
MIT. See [LICENSE](LICENSE).
