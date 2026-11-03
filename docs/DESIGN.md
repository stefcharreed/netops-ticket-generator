# Design

## Purpose
netops-ticket-generator turns a labeled incident record (a JSON "scenario spec") into a practice packet
for network troubleshooting: a syslog spreadsheet, per-device telemetry charts, config diffs, an
end-user ticket and a brief. The spec is also the answer key. Python checks the spec against real
vendor log formats and cross-file consistency rules before rendering anything, so every packet's files
agree with each other and with the hidden answer. Claude Code skills write the spec and grade a
diagnosis against it; the Python package works on its own from the command line.

## Architecture
```
 skill (interview-packet, using log-formats + packet-builder)
   |  writes
   v
 scenario spec  <Keys>/pkt-xxxxxx.json          schema/scenario.schema.json
   |                                            registry/*.yaml
   v                                                 |
 validate(spec, registry) -> findings  <-------------+
   |  any error -> stop, nothing written
   v
 render into <out>/.build-XXXX/ (temp dir)
   logs.xlsx, telemetry_<device>.png, config_diffs.txt and TICKET.md (when present), BRIEF.md
   |
   v
 post-render checks (K3, X1, sanitize on rendered text)
   |  any error -> temp dir removed
   v
 os.replace -> <out>/<YYYY-MM-DD>-pkt-xxxxxx/
 <Keys>/pkt-xxxxxx.manifest.json  (packet_dir + where each id landed)
```
Modules (`src/packetgen/`):
- `spec.py` loads a spec and runs the JSON Schema check.
- `registry.py` loads `registry/*.yaml`, compiles a message template to a regex, fills a template.
- `timebase.py` parses UTC times and renders the per-device syslog header.
- `validate.py` runs every spec rule; `ticket.py` holds the ticket rules; `patterns.py` checks the
  fault-pattern catalog.
- `render/` writes each packet file and returns a manifest (spec id to row, file or line).
- `build.py` is the pipeline above; `sanitize.py` is the leak gate; `cli.py` is the only module that prints.

Every check returns the same finding shape from `findings.py`:
`{"check", "message", "fix", "severity"}`, with severity `error` (blocks) or `warning`.

## CLI
```
python -m packetgen validate SPEC [--registry DIR]
python -m packetgen build SPEC --out DIR [--registry DIR] [--force]
python -m packetgen patterns [--topic T] [--cert C] [--exclude ID ...] [--file F] [--registry DIR]
```
- `validate` prints findings as JSON; exit 1 if any is an error, else 0.
- `build` prints `{ok, packet_dir, findings, manifest}`; exit 0 when `ok`, else 1.
- `patterns` checks the catalog first, then prints matching ids in file order. Exit 0 = ids printed,
  1 = no match, 2 = invalid `--topic`/`--cert` value or invalid catalog (findings on stderr).
- `--registry` defaults to the repo's `registry/`, `--file` to `scenarios/starter.yaml`.

## The scenario spec
Defined by `schema/scenario.schema.json` (`schema_version: 1`). Unknown keys are rejected in every
fixed-shape object; only `topology.entities` names and event `fields` names are free.
- `meta`: `id` (`pkt-` + 6 hex), `style` (`multi-source`), `window {start, end}`, `difficulty`
  (`min_noise`, default 3; `show_diff_notes`, default false; `shuffle_rows`, default 0),
  `allow_unverified`, `brief` (the ask shown to the candidate).
- `topology`: `devices[]` (`hostname`, `role`, `header_style`, `mgmt_ip`, `tz_offset_min`, `clock`
  `ntp|unsynced`, `skew_s` required when unsynced), `links` (hostname pairs), `entities` (named `{mac, ip}`).
- `events[]` (`e1`...): `t`, `device`, `format_id` (registry id), `fields`, `label`, `caused_by`, `signal`.
- `telemetry[]` (`tm1`...): `device`, `metric`, `kind` (`gauge|rate|delta`), `unit`, `interval_s`, `points [[t, v]]`.
- `config_diffs[]` (`cd1`...): `device`, `t_change`, `before`, `after`, `note`.
- `ticket` (optional): see Tickets.
- `answer`: the key (below).

**Labels.** Each event is `root_cause`, `symptom`, `unrelated` or `noise`. This is what the candidate
must reproduce, and what the validator uses to test causality and fairness.

**Causal links.** `caused_by` is a parent id (`e`, `tm` or `cd` + digits) or null; on a symptom's
path it must resolve to an event or config diff.
Symptoms must trace back to the root; unrelated and noise events have no parent. `signal`
(`{series, op, value}`) ties a log line to a telemetry series that must visibly agree with it.

**Answer key.** `root_cause_id` (an event or a config diff), `chain` (ids from the root, in time order),
`fix`, `root_cause_terms` (words that would give the answer away) and `rubric[]` (`id`, `weight`,
`criterion`, `evidence_refs`). The grading skill scores each rubric item full, half or zero.

All spec times are true UTC with `Z` or an offset. A device's `tz_offset_min` and `skew_s` change only
how its log header reads; `received_utc` in the spreadsheet and all telemetry stay true UTC.

## Validator checks
`validate(spec, registry)` runs in this order. S0 failures return immediately. T1 failures return
after the registry checks, because rules that compare times need parseable instants.

| Prefix | Defined in | Ids | What it checks |
|---|---|---|---|
| S0 | `spec.py` | S0 | JSON Schema violation, reported with its JSON path |
| R | `validate.py` | R1-R5 | unknown `format_id`; unverified entry (error, or warning with `allow_unverified`); missing field (error) or extra field (warning), or a half-filled optional section; rendered message fails the entry's regex; entry's `header_style` differs from the device's |
| T | `validate.py` | T1-T4 | naive or unparsable time; event, telemetry point or diff outside `meta.window` (diffs may precede it); effect before its cause; root-cause diff at or after the first symptom |
| C | `validate.py` | C1-C4 | root id unknown or a second `root_cause` label; a symptom whose `caused_by` chain loops, dangles or stops short of the root; unrelated/noise with a parent; `answer.chain` not starting at the root, naming unknown ids or out of time order |
| S | `validate.py` | S1-S4 | points not exactly `interval_s` apart; error/discard/CRC metrics not `rate`/`delta` or negative; `cpu_1min`/`cpu_5min` peaking above a shorter window on the same device; an event's `signal` not met within one interval of the event, or its series missing or on another device |
| E | `validate.py` | E1-E2 | device not in topology; a field ending in `ip`/`mac` whose value is not a mgmt IP or declared entity |
| K | `validate.py`, `build.py` | K1-K3 | rubric evidence id unknown; duplicate rubric id; evidence id not in any rendered file (post-render) |
| L | `validate.py` | L1 | a `root_cause_terms` entry appears in `meta.id`, `meta.brief`, ticket text, or a diff note when notes are shown |
| N | `validate.py` | N1 | fewer unrelated/noise events than `min_noise` |
| TK | `ticket.py` | TK1-TK5 | see Tickets |
| Q | `validate.py` | Q1 | warning: the root cause is the single most severe line |
| X | `build.py` | X1 | a `received_utc` cell in `logs.xlsx` is not a date cell (post-render) |
| B | `build.py` | B1 | a folder for this packet id already exists (any date) and `--force` was not given |
| Z | `sanitize.py` | Z1-Z5 | see Sanitize gate |
| P | `patterns.py` | P1-P6 | see Pattern catalog |

Warnings are R2 (with `allow_unverified`), R3 (extra field), Q1, TK4 and TK5; everything else is an error.
The packet-builder skill's fix table maps each id to a repair.

## Log-format registry
`registry/*.yaml` holds normalized syslog message formats, loaded by `load_registry()` into
`{id: entry}` (duplicate ids raise). The files were generated by `scripts/import_registry.py` from
source YAMLs that are not included in this repo, so changes come as hand-reviewed edits to
`registry/*.yaml` that keep the fields below. Entry fields:
- `id`: `PREFIX:TOKEN`, e.g. `IOS:LINK-3-UPDOWN`, `ASA:106023`, `ISCDHCPD:no-free-leases`.
  A spec event references it as `format_id`; a pattern lists it under `registry_ids`.
- `vendor`, `severity` (syslog number or null), `example`, `source_url`.
- `message`: the template from the vendor token (`%FAC-SEV-MNEM:`, `%ASA-...`) or `program[pid]:` tag on.
  `{name}` is a placeholder (repeats get `_2`, `_3`; inline choices become `choice_N`);
  `[[ ... ]]` is an optional section, dropped when all its fields are empty and an error (R3) when half-filled.
- `placeholders`: name to regex; no regex means free text (`.*?`). Whitespace runs match any whitespace.
- `verified`: true only when the source was checked and the entry's own example matches its own
  pattern. `demoted_reason` says why a source-verified entry was demoted (null otherwise).
  The importer demotes entries that fail; it never drops them.
- `header_style`: which header the line needs. Supported styles (`timebase.STYLES`):

| Style | Header shape | Id prefixes |
|---|---|---|
| `ios` | `[seq: ]Mon dd HH:MM:SS.mmm ZONE: ` | IOS, C9800 |
| `nxos` | `YYYY Mon dd HH:MM:SS host ` | NXOS |
| `asa` | `Mon DD YYYY HH:MM:SS host : ` | ASA, FTD |
| `bsd` | `Mon dd HH:MM:SS host ` | ISE, ISCDHCPD, JUNOS, CHRONY, NTPD, UNBOUND |
| `meraki` | `<epoch seconds>.<nanoseconds> host ` | MERAKI |

`null` means not renderable yet: PANOS, FGT, ARUBA, KEA, FREERADIUS, BIND, WINDHCP, WINDNS, IEEE80211, EAPOL.
Every header comes from the event's UTC instant plus the device's offset and (if unsynced) skew.

## Tickets
`ticket` is optional in the schema; the interview-packet skill requires one for new packets.
- `persona`: only `end_user` (role "end user", evidence `anecdote`, hedging, never names gear).
- `text`: what the user reported. `TICKET.md` shows only the persona's role and this text.
- `misdirection[]`: `{kind, claim, true_because}`. Kinds (`ticket.MISDIRECTION_KINDS`): `misattribution`,
  `scope`, `coincidence`, `omission`, `stale`. Each claim is true of the scenario but points the wrong
  way; `true_because` explains it. Misdirection is answer material and is never rendered.

Checks (`ticket.py`, all run from `validate()`):
- **TK1** (error): the text names a device-like token (`EDGE1`, `SW-L3`) that is not a topology hostname,
  an IPv4 address that is not a mgmt IP or entity IP, or any interface name (`Gi1/0/1`, `Vlan10`; lowercase only in slot/port form, `gi1/0/1`).
- **TK2** (error): an `anecdote` persona quotes device output (`show ...`, `traceroute`, `config t`).
- **TK3** (error): a misdirection `claim` is under 4 words, or is not in the text (case and whitespace normalized).
- **TK4** (warning): no misdirection planted.
- **TK5** (warning): the text shares 2 or more word stems (first four letters) with `answer.fix` and
  `root_cause_terms`, not counting stems already in `meta.brief` or symptom-event fields.

L1 also checks the ticket text against `root_cause_terms`.

## Pattern catalog
`scenarios/starter.yaml` lists fault patterns: seeds for a scenario, not scripts. Required keys
(`patterns.REQUIRED`): `id`, `symptom`, `root_cause`, `registry_ids`, `red_herrings`, `topic`, `cert`.
- Topics: `stp`, `trunk`, `acl`, `aaa`, `ntp`, `ospf`, `eigrp`, `bgp`, `fhrp`, `port-security`.
- Certs: `ENCOR`, `ENARSI`, `none`.

`packetgen patterns` runs `check_patterns()` before listing (all errors):
P1 unknown registry id; P2 registry id not verified; P3 registry id's `header_style` not renderable;
P4 `topic` or `cert` missing or not allowed; P5 duplicate pattern id; P6 required key missing.
The interview-packet skill filters with `--topic`/`--cert`, excludes the last 3 patterns from its
history file, and picks one with a real random draw.

## Sanitize gate
`sanitize.py` keeps real-looking identifiers out of packets and out of git.
- **Z1** IPv4 outside RFC 1918, RFC 5737, loopback, multicast, `0.0.0.0/8` and `255.0.0.0/8` (masks).
  Version strings like `17.9.4` do not match; octets over 255 are ignored.
- **Z2** MAC outside the RFC 7042 documentation range, STP/LLDP and IPv4 multicast, broadcast and
  all-zero, in colon, dash or dotted notation.
- **Z3** file suffix `.xlsx`, `.pdf`, `.pcap` or `.pcapng`: binary artifacts can't be text-scanned.
- **Z4** a macOS, Linux or Windows home-directory path (`~/` paths and URLs are fine).
- **Z5** a term from the gitignored `.sanitize-deny` file (one per line, `#` comments), matched
  case-insensitively across line wraps.

Where it runs: `scripts/pre-commit` on staged files (`git config core.hooksPath scripts`), CI on every
tracked file, and `build.py` on rendered text (xlsx message column, `config_diffs.txt`, `TICKET.md`,
`BRIEF.md`; Z1, Z2 and Z4 apply there).

## Design decisions
- The spec is the answer key: one labeled record, so the validator and the grader read the same truth.
- Checks return plain finding dicts and never print: the same functions serve the CLI and the skills.
- All spec times are UTC; headers derive from offset and skew: files agree, and a skewed clock is visible
  as a header that disagrees with `received_utc`.
- Naive timestamps are rejected (T1) and time rules skipped: a naive time has no comparable instant.
- Unverified formats are errors unless opted in: invented log lines are the main realism risk.
- The importer demotes rather than drops: the data stays visible with the reason.
- Render in a temp dir inside the output directory, then `os.replace`: a failed build leaves nothing,
  and the move stays on one filesystem.
- One folder per packet id, never overwritten without `--force`: it may hold `GRADE.md`.
- The manifest is written next to the spec: grading finds the packet folder without guessing the date.
- Misdirection and diff notes are hidden by default: they are answer material.
- Diffs are rendered with full context: the stanza header shows which interface changed.
- Row shuffling is seeded by `meta.id`: reordering is realistic but reproducible.
- Error counters must be rate or delta: a raw Counter32 graph says nothing.
- Q1, TK4 and TK5 are warnings: they are realism heuristics, not correctness rules.
- TK5 ignores stems the candidate is already given: sharing them leaks nothing.
- `build` imports matplotlib lazily: `validate` stays fast.
- The skill draws patterns at random and generates the key in a subagent: no judgment bias in the pick,
  and the key stays out of the user's transcript.
- Registry and scenario text is data, never instructions: a contributed file must not steer the model.
- Binary files are blocked from git: they can't be text-scanned.

## Known gaps
- No verified VRRP or IOS NAT log ids yet.
- PAN-OS ids are verified but not renderable (header style unsupported).
- Gear-validated: none.

## Verification status
- Fixture-tested: the pytest suite under `tests/`.
- Live generation runs were built and leak-checked (no answer text in the packet).
- Generated packets have not yet been graded against real attempts.
- Gear-validated: none. Nothing here has been checked against real devices.
- Log formats come from a registry checked against vendor documentation, upstream source code and
  parser fixtures. Each entry has a source URL and a `verified` flag.
