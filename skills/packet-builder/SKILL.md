---
name: packet-builder
description: Write and repair netops-ticket-generator scenario specs (the JSON labeled-incident record behind each practice packet) and fix validator findings by check id. Use when building or debugging an interview packet spec, or when `packetgen validate`/`build` reports findings.
---

# Packet builder

Schema: `<repo>/schema/scenario.schema.json`. Worked example (read it before writing one):
`<repo>/tests/fixtures/stp_dhcp_cascade.json` (ticket example: `<repo>/tests/fixtures/ticket.json`). `<repo>` = the `packetgen_repo:` line in `~/.config/claude-skills/profile.md`.

## Spec in one screen
- `meta`: `id` (`pkt-` + 6 hex), `style` (`multi-source`), `window {start,end}` (UTC, `Z`), `difficulty
  {min_noise, show_diff_notes, shuffle_rows}`, `allow_unverified`, `brief` (the ask; never names the cause).
- `topology`: `devices[]` (`hostname`, `role`, `header_style`, `mgmt_ip`, `tz_offset_min`, `clock`, `skew_s` if unsynced),
  `links`, `entities` (every MAC/IP that appears in a field must be declared here or be a mgmt IP).
- `events[]`: `id` (`e1`…), `t`, `device`, `format_id` (registry id), `fields`, `label`
  (`root_cause|symptom|unrelated|noise`), `caused_by` (parent id or null), `signal` (`{series, op, value}` or null).
- `telemetry[]`: `id` (`tm1`…), `device`, `metric`, `kind` (`gauge|rate|delta`), `unit`, `interval_s`, `points [[t, v]]`.
- `config_diffs[]`: `id` (`cd1`…), `device`, `t_change`, `before`, `after`, `note`.
- `answer`: `root_cause_id`, `chain` (starts at root, time-ordered), `fix`, `root_cause_terms`, `rubric[]`
  (`id`, `weight`, `criterion`, `evidence_refs`).
- `ticket` (optional in the schema, mandatory for new packets): `persona` (`end_user`), `text` (what the user
  reported), `misdirection[]` (`kind` = `misattribution|scope|coincidence|omission|stale`, `claim` = a sentence
  copied exactly from `text`, `true_because`).

## Time, clocks and judgment calls
- **Every time in the spec is true UTC.** `tz_offset_min` and `skew_s` change only how that device's *log
  header* reads. The xlsx `received_utc` column (the collector's clock) and all telemetry stay true UTC, so a
  skewed device shows up as its header disagreeing with `received_utc`.
- **Realistic skew:** a device that lost NTP drifts seconds to a few minutes (about 20–300 s). Hours of offset
  usually means a wrong time zone, so model that with `tz_offset_min`, not `skew_s`.
- **Config changes may land before `window.start`.** Changes often go in minutes or hours before symptoms.
  They must still come before the first symptom (T4) and can't be after `window.end` (T2).
- **Declare every address**, including IPs inside free-text fields (e.g. a `who` field). E2 only checks fields
  whose names end in `ip` or `mac`, but undeclared addresses still let files disagree.
- **`root_cause_terms`:** 2–4 distinctive words or phrases that would give the answer away if they showed up in
  the brief: the command or feature (`bpdufilter`, `allowed vlan`) or the failing component (`RADIUS`). Not
  generic words the brief needs (`network`, `slow`, `switch`). L1 matches them case-insensitively against the
  id, the brief, the ticket text and any visible diff notes.
- **Ticket:** every claim is true of the scenario; misdirection misleads, it never lies. Plant at least one.
  The `end_user` describes what they noticed, never gear, commands or the cause. Pick the symptom from the
  fault family:
  - routing: "cannot reach something that used to be reachable"
  - VLAN/STP/trunk: "can reach some machines and not others, with no pattern they can see"
  - FHRP: "loses the network briefly and then it comes back on its own"
  - ACL/NAT/PBR: "finds one application broken while everything else works"
  The misdirection stays in the key: it is never rendered into the packet and only GRADE.md reveals it.
- **CPU series** must use the metric names `cpu_5s`, `cpu_1min`, `cpu_5min` exactly; other names skip S3.

## Pattern catalog
Each pattern in `<repo>/scenarios/starter.yaml` carries `topic` (stp, trunk, acl, aaa, ntp, ospf, eigrp, bgp, fhrp,
port-security) and `cert` (`ENCOR`, `ENARSI` or `none`). `packetgen patterns` lists pattern ids and checks the
catalog first (filters: `--topic`, `--cert`, `--exclude ID...`; also `--file`, `--registry`). Exit 0 = ids printed,
1 = no match, 2 = catalog invalid (findings on stderr).

## Fixing findings
| Check | Means | Fix |
|---|---|---|
| S0 | schema violation | match the schema; the message gives the JSON path |
| P1–P6 | catalog (all errors): unknown registry id / id not verified / header_style not renderable (ios, nxos, asa, bsd, meraki only) / topic or cert missing or invalid / duplicate pattern id / required key missing (id, symptom, root_cause, registry_ids, red_herrings, topic, cert) | fix the entry in `scenarios/starter.yaml`; use a verified, renderable registry id |
| R1–R5 | unknown id / unverified / missing or extra field / value breaks pattern / header style mismatch | see **log-formats** |
| T1–T4 | naive time / outside window / effect before cause / change after first symptom | use `Z` times; reorder |
| C1–C4 | root missing or doubled / chain can't reach root / noise has a parent / answer chain wrong | fix labels and `caused_by` |
| S1–S4 | uneven points / error counter not rate or negative / CPU 5 min peak above 1 min / signal not visible | regenerate the series |
| E1–E2 | unknown device / undeclared MAC or IP | declare it in `topology` |
| K1–K3 | evidence ref unknown / duplicate rubric id / ref not rendered | point at real ids |
| L1 | a root-cause term leaks into id, brief, ticket text or a visible note | reword |
| N1 / Q1 | too little noise / root is the loudest line (warning) | add noise; quieter root evidence |
| TK1 | ticket names a device, IP or interface not in topology | name only known devices/addresses; an end_user shouldn't name gear at all; tokens like O365/M365, W10 or room numbers (B204) trip TK1, so spell them out (Office 365, Windows 10, room 204) |
| TK2 | end_user ticket quotes device output (show/traceroute/config) | describe what the user noticed |
| TK3 | misdirection claim under 4 words, or not found in the ticket text | plant a full sentence; copy it exactly |
| TK4 | no misdirection planted (warning) | plant one true-but-misleading statement |
| TK5 | ticket reuses 2+ word stems from `answer.fix`/`root_cause_terms` (warning); stems already in `meta.brief` or symptom-event fields do not count | describe the symptom, not the cause |
| X1, Z1, Z2, B1 | xlsx date cell / non-doc IP / non-doc MAC / packet exists | build-side; B1 needs `--force` |
