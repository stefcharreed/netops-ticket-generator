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
   logs.xlsx, telemetry_<device>.png, config_diffs.txt and TICKET.md (when present), BRIEF.md,
   capture_<device>_<interface>.pcap (when the spec has a capture, then a tshark read-back)
   |
   v
 post-render checks (K3, X1, sanitize on rendered text and the tshark dump)
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
- `capture.py` resolves capture endpoints and runs PK1-PK5; `capture_kinds.py` is the flow-kind catalog
  (param schemas, endpoint needs, display filters); `render/capture.py` writes the pcap (the only module
  that imports dpkt); `tshark.py` is the read-back.
- `build.py` is the pipeline above; `sanitize.py` is the leak gate; `cli.py` is the only module that prints.

Every check returns the same finding shape from `findings.py`:
`{"check", "message", "fix", "severity"}`, with severity `error` (blocks) or `warning`.

## CLI
```
python -m packetgen validate SPEC [--registry DIR]
python -m packetgen build SPEC --out DIR [--registry DIR] [--force] [--no-tshark]
python -m packetgen patterns [--topic T] [--cert C] [--exclude ID ...] [--show-capture ID] [--file F] [--registry DIR]
```
- `validate` prints findings as JSON; exit 1 if any is an error, else 0.
- `build` prints `{ok, packet_dir, findings, manifest}`; exit 0 when `ok`, else 1.
- `build --no-tshark` skips the capture's tshark read-back and adds the PK6 warning "read-back skipped";
  the manifest then records `"tshark_checked": false`.
- `patterns` checks the catalog first, then prints matching ids in file order. Exit 0 = ids printed,
  1 = no match, 2 = invalid `--topic`/`--cert` value or invalid catalog (findings on stderr).
  `--show-capture ID` prints that pattern's capture hint as JSON instead (exit 1 when there is none).
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
- `capture` (optional): see Capture.
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
| P | `patterns.py` | P1-P7 | see Pattern catalog |
| PK | `capture.py`, `build.py` | PK0-PK7 | see Capture |

Warnings are R2 (with `allow_unverified`), R3 (extra field), Q1, TK4, TK5 and the PK6 "read-back skipped"
notice; everything else is an error.
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
P4 `topic` or `cert` missing or not allowed; P5 duplicate pattern id; P6 required key missing;
P7 the optional `capture` hint is invalid (not a mapping, missing `kinds`/`evidence_kind`/`evidence`, a kind
not in the flow catalog, or an `evidence_kind` that is not among `kinds` or has no symptom rule).
The interview-packet skill filters with `--topic`/`--cert`, excludes the last 3 patterns from its
history file, and picks one with a real random draw.

## Capture
An optional synthetic SPAN capture, written as `capture_<device>_<interface>.pcap` (`/` and `:` in the
interface become `-`). It is evidence the candidate reads in Wireshark; the spec stays the answer key.
Install the optional extra for it: `pip install -e '.[capture]'` (dpkt), plus tshark 4.2 or newer for the read-back.

**Spec block** (`capture`, all keys required except `noise`):
- `device`, `interface`: where the SPAN destination port sits. `peer`, `peer_interface`: the device and
  port on the other end of the link (its MAC is the BPDU source). The pair must be in `topology.links`.
- `direction`: `both` only. `tagged`: `false` only (no VLAN-tagged captures yet). Both are pinned by the schema.
- `start`, `end`: UTC bounds, inside `meta.window`. `noise`: `low|medium|high` (default `medium`).
- `flows[]`: `id` (`pk1`...), `kind`, `t`, `src`, `dst`, `via` (optional, may be null), `params`, `label`
  (`symptom|unrelated|noise`), `caused_by`. Flows join the same causal graph as events: a symptom flow must trace
  back to the root, and unrelated/noise flows have no parent. Rubric `evidence_refs` may cite a `pk` id.
- Topology side: a device may declare `interfaces[]` (`name`, `mac`, optional `ip`, optional `vlan`).

**Endpoint names.** An endpoint is a `topology.entities` name, `HOST:IFNAME` (a declared device interface), or
a bare `HOST` when that device has exactly one interface; resolution tries them in that order. `src` and `dst`
need the attributes the kind lists (MAC and IP for `src`, IP for `dst`). `via` is the next-hop gateway: frames
toward `dst` go to the `via` MAC and routed replies come back from it with TTL one lower; with no `via` they go
straight to `dst`. `arp` ignores `via` (link-local broadcast).

**Kinds and filters** (`capture_kinds.py`; only `radius_request` has a symptom rule, so only it can be labeled
`symptom`). Filters are catalog constants keyed by `params.outcome`:

| Kind | Outcome | Display filter that must match |
|---|---|---|
| `radius_request` | `no_response` | `radius.code == 1 && !radius.rspframe` |
| `radius_request` | `accept` | `radius.code == 2` |
| `radius_request` | `reject` | `radius.code == 3` |
| `arp` | `reply` | `arp.opcode == 2` |
| `arp` | `no_reply` | `arp.opcode == 1` |
| `arp` | `gratuitous` | `arp.isgratuitous` |
| `dns_query` | `ok` | `dns.flags.response == 1 && dns.flags.rcode == 0` |
| `dns_query` | `nxdomain` | `dns.flags.rcode == 3` |
| `dns_query` | `servfail` | `dns.flags.rcode == 2` |
| `dns_query` | `timeout` | `dns.flags.response == 0 && !dns.response_in` |

Params are validated per kind (PK4). `radius_request` needs `outcome`, `username`, `client` (an entity with a
MAC, sent as Calling-Station-Id) and `nas_port`, with optional `retries`, `timeout_s`, `auth_port`.
`dns_query` needs `outcome` and `name` (`.test` or under example.com/net/org); `ok` also needs `answer`.
AAAA answers are not supported yet. A gratuitous `arp` needs `dst == src`.

**Timing.** Each flow starts at its `t`; its span (`span_s`) is the time to its last frame: a `no_response`
RADIUS flow lasts `timeout_s * retries` seconds (retransmits every `timeout_s`), a replied flow tens of
milliseconds. The whole span must fit inside `capture.start..end` (PK2). Reply delays are seeded jitter.

**Noise and SPAN realism.** The renderer adds background traffic so the symptom is not the only thing in the
file: implicit noise is a spanning-tree BPDU from the peer every 2 s at `medium` and `high`, plus ARP
request/reply pairs among declared hosts in the capture and peer subnets (every 30, 10 or 3 s for `low`,
`medium`, `high`). Flows add their own explicit noise. Frames are untagged and zero-padded to 60 bytes, with
consistent source and destination MACs, TTLs (255 for switch-sourced, 64 for hosts) and per-sender IP ids.
All randomness is seeded from `meta.id` and the flow id, so the same spec gives the same bytes.

**Manifest frame map.** `<Keys>/pkt-xxxxxx.manifest.json` holds `capture_<...>.pcap`: `{pk id: [frame numbers]}`
(1-based, labeled flows only; implicit noise is unlisted). Grading cites `capture_<...>.pcap frame N` from it.
The manifest also records `"tshark_checked"`: false under `--no-tshark`, or when the read-back did not run.

**Checks.**
- **PK0** (error): the capture extra (dpkt) is not installed, so the pcap cannot be rendered.
- **PK1** (error): `capture.device`/`peer` or their interfaces are not in topology, or the pair is not linked.
- **PK2** (error): `start` is not before `end`, the capture is outside `meta.window`, or a flow plus its span
  does not fit inside `start..end`.
- **PK3** (error): `src`/`dst`/`via` does not resolve, lacks the MAC or IP the kind needs, or a RADIUS
  `client` / DNS `answer` is not a declared entity with a MAC / IP.
- **PK4** (error): `params` break the kind's schema, a gratuitous ARP has `dst != src`, a DNS `ok` has no
  `answer`, or `qtype` is `AAAA` with outcome `ok`.
- **PK5** (error): a symptom flow of a kind with no symptom rule; a RADIUS flow that contradicts the log. Per
  (NAS device, server ip), a dead period runs from 30 s before an `IOS:RADIUS-4-RADIUS_DEAD` event to the next
  `IOS:RADIUS-4-RADIUS_ALIVE` (open-ended if none). An unanswered (`no_response`) request must fall inside a dead
  period: the DEAD event is at most 30 s after the request, or any time before it with no ALIVE in between. An
  answered (`accept`/`reject`) request is an error when DEAD <= t < the next ALIVE.
- **PK6** (error unless noted): the tshark read-back failed. tshark is missing or older than 4.2; a display
  filter or the `-V` dump failed or came back empty; tshark flags malformed or expert-error frames (any frame);
  tshark read a different frame count than the renderer wrote; or a symptom flow's expected filter matches
  none of its own frames. Under `--no-tshark` it is a warning, "read-back skipped".
- **PK7** (error): the capture has more than 5,000 frames.

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
- Binary files are blocked from git: they can't be text-scanned. A built pcap is checked through tshark's
  text dump instead, which goes through the same sanitize scan before the packet is moved into place.
- Display filters come from the code's catalog, never from spec text: nothing the model writes reaches the
  tshark argv, so a spec cannot steer the external program.
- The tshark read-back is two-pass: first it reads frame counts, bad frames and filter matches with `-T fields`
  (the independent check that real dissectors agree with the renderer), then it takes a `-V` dump for the
  sanitize scan. Both run with `-2 -n` and `TZ=UTC`.
- dpkt is optional: `validate` never needs it, only `build` of a spec with a `capture`, and PK0 reports its absence.
- The capture is evidence the candidate can read in Wireshark, so its text (usernames, DNS names) is held to the
  same no-leak rule as the brief (L1 checks flow string params against `root_cause_terms`).

## Known gaps
- No verified VRRP or IOS NAT log ids yet.
- PAN-OS ids are verified but not renderable (header style unsupported).
- Capture flow kinds are `radius_request`, `arp` and `dns_query` only; no VLAN-tagged captures; AAAA answers unsupported.
- Gear-validated: none.

## Verification status
- Fixture-tested: the pytest suite under `tests/`.
- Live generation runs were built and leak-checked (no answer text in the packet).
- Generated packets have not yet been graded against real attempts.
- Captures: synthetic, protocol-checked and tshark-checked; not gear-validated. Only symptom flows are checked
  against their expected display filter; every frame is checked for malformed and expert errors.
- Gear-validated: none. Nothing here has been checked against real devices.
- Log formats come from a registry checked against vendor documentation, upstream source code and
  parser fixtures. Each entry has a source URL and a `verified` flag.
