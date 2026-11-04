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
- `topology`: `devices[]` (`hostname`, `role`, `header_style`, `mgmt_ip`, `tz_offset_min`, `clock`, `skew_s` if unsynced,
  optional `interfaces[]` of `{name, mac, ip?, vlan?}` for anything a capture endpoint or SPAN port uses),
  `links`, `entities` (every MAC/IP that appears in a field must be declared here or be a mgmt IP).
- `events[]`: `id` (`e1`…), `t`, `device`, `format_id` (registry id), `fields`, `label`
  (`root_cause|symptom|unrelated|noise`), `caused_by` (parent id or null), `signal` (`{series, op, value}` or null).
- `telemetry[]`: `id` (`tm1`…), `device`, `metric`, `kind` (`gauge|rate|delta`), `unit`, `interval_s`, `points [[t, v]]`.
- `config_diffs[]`: `id` (`cd1`…), `device`, `t_change`, `before`, `after`, `note`.
- `capture` (optional synthetic SPAN capture; worked example `<repo>/tests/fixtures/radius_capture.json`):
  `device`, `interface` (the SPAN port), `peer`, `peer_interface` (the linked device and port), `direction`
  `both`, `start`, `end` (UTC, inside the window), `tagged` `false`, `noise` (`low|medium|high`), and `flows[]`
  of `{id (pk1…), kind, t, src, dst, via, params, label (symptom|unrelated|noise), caused_by}`. Kinds:
  `radius_request`, `arp`, `dns_query`; only `radius_request` can be a `symptom`. An endpoint is an entity
  name, `HOST:IF` (a declared interface, e.g. `ACC-SW1:Vlan100`) or a bare `HOST` with exactly one interface.
  `via` is the gateway MAC that frames toward `dst` use (null for same-subnet traffic). Flows are nodes in the
  causal graph like events, and rubric `evidence_refs` may cite a `pk` id.
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

## Writing a capture
- Add a few noise flows (an accepted RADIUS request for another user, a DNS lookup, an ARP with no reply) so
  the symptom is not the only conversation. The renderer adds BPDUs and background ARP on its own.
- Think like a SPAN port: it sits on `capture.interface`, so flows must plausibly cross that link. Put `via`
  on traffic that crosses the gateway; leave it null for same-subnet traffic.
- A `no_response` RADIUS flow lasts `timeout_s * retries` seconds, all of which must fit before `capture.end`,
  and the switch must log `IOS:RADIUS-4-RADIUS_DEAD` for that server within 30 s after it (PK5).
- No leaks: usernames and DNS names are plain evidence the candidate reads. Never put a `root_cause_terms`
  word in them (L1), and use `.test` or example.com/net/org names and RFC 7042 MACs / RFC 5737 or 1918 IPs.
- `<repo>/.venv/bin/python -m packetgen patterns --show-capture <pattern id>` prints a pattern's capture hint
  (kinds, evidence kind, what the evidence should show). It is a seed, like the rest of the catalog.
- Build without `--no-tshark` for anything you hand out; `--no-tshark` is for iterating only.

## Pattern catalog
Each pattern in `<repo>/scenarios/starter.yaml` carries `topic` (stp, trunk, acl, aaa, ntp, ospf, eigrp, bgp, fhrp,
port-security) and `cert` (`ENCOR`, `ENARSI` or `none`). `packetgen patterns` lists pattern ids and checks the
catalog first (filters: `--topic`, `--cert`, `--exclude ID...`; also `--file`, `--registry`). Exit 0 = ids printed,
1 = no match, 2 = catalog invalid (findings on stderr). `--show-capture ID` prints that pattern's capture hint.

## Fixing findings
| Check | Means | Fix |
|---|---|---|
| S0 | schema violation | match the schema; the message gives the JSON path |
| P1–P7 | catalog (all errors): unknown registry id / id not verified / header_style not renderable (ios, nxos, asa, bsd, meraki only) / topic or cert missing or invalid / duplicate pattern id / required key missing (id, symptom, root_cause, registry_ids, red_herrings, topic, cert) / P7 capture hint invalid (needs `kinds`, `evidence_kind`, `evidence`; kinds in the flow catalog; evidence kind among them and with a symptom rule) | fix the entry in `scenarios/starter.yaml`; use a verified, renderable registry id |
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
| PK0 | capture extra (dpkt) not installed | `pip install -e '.[capture]'` in the repo's venv |
| PK1 | capture device, peer or interface not in topology, or the pair isn't linked | declare the device, interface and link |
| PK2 | capture start not before end, outside the window, or a flow plus its span doesn't fit | move the flow or widen the capture inside the window |
| PK3 | endpoint doesn't resolve or lacks the MAC/IP the kind needs (RADIUS client needs an entity with a MAC; DNS answer needs an IP) | declare it under `entities` or the device's `interfaces[]` |
| PK4 | flow params break the kind's schema, gratuitous ARP with dst != src, DNS ok without answer, or AAAA ok | fix the params; AAAA answers are unsupported |
| PK5 | symptom on a kind with no symptom rule, or a RADIUS flow whose outcome disagrees with the RADIUS_DEAD/ALIVE log events | label it noise or use `radius_request`; add the DEAD event within 30 s after the first request, or move the flow |
| PK6 | tshark missing or older than 4.2, a filter/dump failure, malformed or expert-error frames, a symptom flow whose expected filter matches none of its frames; a warning "read-back skipped" under `--no-tshark` | install tshark 4.2+; fix the flow params; rebuild without `--no-tshark` before handing out |
| PK7 | capture over 5,000 frames | shorten `start..end` or lower `noise` |
| X1, Z1, Z2, B1 | xlsx date cell / non-doc IP / non-doc MAC / packet exists | build-side; B1 needs `--force` |
