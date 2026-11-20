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
  `links` (pairs of `HOST` or `HOST:IFNAME`; the interface is the diagram's port label), `entities` (every MAC/IP that
  appears in a field must be declared here or be a mgmt IP). Network-docs extras, all optional: device `icon`,
  entity `kind` and `attached {device, interface?, vlan?}`, and one `documented` override (see Network docs).
- `events[]`: `id` (`e1`…), `t`, `device`, `format_id` (registry id), `fields`, `label`
  (`root_cause|symptom|unrelated|noise`), `caused_by` (parent id or null), `signal` (`{series, op, value}` or null).
- `telemetry[]`: `id` (`tm1`…), `device`, `metric`, `kind` (`gauge|rate|delta`), `unit`, `interval_s`, `points [[t, v]]`.
- `config_diffs[]`: `id` (`cd1`…), `device`, `t_change`, `before`, `after`, `note`.
- `capture` (optional synthetic capture; worked examples `<repo>/tests/fixtures/radius_capture.json` (native
  SPAN) and `<repo>/tests/fixtures/trunk_pruned_capture.json` (replicate SPAN on a trunk)): `method`
  (`span|erspan`), `reason` (the technician's why, naming `device`), `span {encapsulation native|replicate,
  native_vlan?, trunk_vlans}` or `erspan {origin_ip, analyzer, session, erspan_id, via?}`, `device`,
  `interface` (the monitored port), `peer` (the linked device, or an entity attached to that port),
  `peer_interface` (required for a device peer), `direction` `both`, `start`, `end` (UTC, inside the window),
  `noise` (`low|medium|high`), and `flows[]` of `{id (pk1…), kind, t, src, dst, via, vlan?, params, label
  (symptom|unrelated|noise), caused_by}`. Kinds: `radius_request`, `arp`, `dns_query`, `stp_bpdu`, `cdp`,
  `hsrp_hello`, `dhcp`; all but `dns_query` can be a `symptom` (each needs its PK5 evidence). Worked Layer 2
  examples: `<repo>/tests/fixtures/{loop_bpdufilter,port_security,native_vlan,hsrp_flap}_capture.json`.
  An endpoint is an entity
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
- Pick the method from the pattern hint's `methods` the way a technician would for this topology: a local SPAN
  when the analyzer can sit on the switch, `encapsulation replicate` when tags or BPDUs matter (a trunk, an STP
  fault), ERSPAN when the analyzer is a routed hop or more away. Then write `reason` like a tech's note in the
  ticket: where, which method, and why that spot (e.g. "ERSPAN from ACC-SW1 Gi1/0/48: the analyzer sits in the
  data center, a routed hop away, so a local SPAN can't reach it."). Name the device; never hint at the cause.
- Add one rubric item about reading the frames that cites the symptom `pk` id (K4): what the candidate should
  see in the capture (tags, the GRE-wrapped request, the unanswered retransmits), not the method's name.
- Add a few noise flows (an accepted RADIUS request for another user, a DNS lookup, an ARP with no reply) so
  the symptom is not the only conversation. The renderer adds BPDUs (replicate SPAN only, one per trunk VLAN)
  and background ARP on its own.
- `stp_bpdu` (loop): only a replicate SPAN sees BPDUs (PK8). The classic evidence is the switch's own BPDU
  coming back in on the edge port (src `HOST:<another port>`, dst the monitored port); PK5 wants the
  guard-to-filter edit on the monitored port in `config_diffs` before it.
- `dhcp`: set `via` to the client VLAN's gateway (the relay). A `no_offer` symptom needs an
  `ISCDHCPD:no-free-leases` event for the client MAC within the flow's span + 30 s; `copies` shows a loop
  replaying each DISCOVER. Watch the 5,000-frame cap.
- `cdp`: `native_vlan` is what the sender announces; CDP rides VLAN 1. A symptom needs a
  `CDP-4-NATIVE_VLAN_MISMATCH` on `capture.device` within 60 s with matching VLAN fields. Put the native-VLAN
  edit on `capture.peer`'s `peer_interface` stanza so the far end's BPDUs and CDP tag the way the gear would.
- `hsrp_hello`: one flow per router per period, `outcome` = its state then; each symptom hello needs the
  sender's latest `HSRP-5-STATECHANGE` for that interface and group to say the same state.
- Port security: capture the desk port with an entity `peer`, attach the second device to the same port, and
  log `PSECURE_VIOLATION` for its MAC (Cisco-dotted, as declared, so E2 matches) within 5 s of its first
  frame, then `PM-4-ERR_DISABLE` for the port: the capture stops there, and a symptom after it is PK8.
- An `arp` symptom (an unanswered gateway ARP on a pruned VLAN) needs a config diff on `capture.peer` before the
  flow whose `interface <peer_interface>` stanza has, in `after`, a plain `switchport trunk allowed vlan 1,10` list
  without the flow's VLAN, and no later diff on that port that restores it (PK5), and the
  flow's VLAN in `span.trunk_vlans` (PK9). The renderer then stops that VLAN's BPDUs and ARP answers too.
- Think like a SPAN port: it sits on `capture.interface`, so flows must plausibly cross that link. Put `via`
  on traffic that crosses the gateway; leave it null for same-subnet traffic.
- A `no_response` RADIUS flow lasts `timeout_s * retries` seconds, all of which must fit before `capture.end`,
  and it must sit inside a dead period (PK5): the switch logs `IOS:RADIUS-4-RADIUS_DEAD` for that server at most
  30 s after the request, or any time before it with no `RADIUS_ALIVE` in between. An `accept`/`reject` flow must
  not fall between a DEAD and its next ALIVE.
- A symptom flow `caused_by` the DEAD event must start at or after that event (T3 applies at the flow's first
  frame). The 30 s lead half of PK5 is usable only when the flow's cause is earlier than the DEAD event, for
  example a config-diff root. Assumes IOS `radius-server deadtime 0` (the default): the switch tries the dead
  primary first on every new authentication, then fails over, so put an accepted flow to the secondary after
  an unanswered attempt sequence to the primary has timed out. Not checked against gear.
- No leaks: usernames and DNS names are plain evidence the candidate reads. Never put a `root_cause_terms`
  word in them (L1), and use `.test` or example.com/net/org names and RFC 7042 MACs / RFC 5737 or 1918 IPs.
- `<repo>/.venv/bin/python -m packetgen patterns --show-capture <pattern id>` prints a pattern's capture hint
  (kinds, evidence kind, what the evidence should show). It is a seed, like the rest of the catalog.
- Build without `--no-tshark` for anything you hand out; `--no-tshark` is for iterating only.

## Network docs (NETWORK.md + topology.png)
Every packet gets the network **as documented**: a Cisco-style diagram, a documented addressing table and, with
`meta.mac_table: true`, a documented MAC table. They're drawn from `topology` only, so they never show the fault.
- Name both ends of every link (`ACC-SW1:GigabitEthernet1/0/49`). Attach the clients and servers the story uses
  (`attached`), so they sit under their switch; anything unattached goes in a side column.
- Set `meta.mac_table: true` for Layer 2 stories: ARP, DHCP, 802.1X/RADIUS, port security, MAC flapping, STP.
  MAC rows come from entities that have a `mac` and an `attached` port.
- Icons come from `role` keywords (router, firewall/asa, core/distribution → L3 switch, access/switch, wlc, ap)
  and entity names (ise/radius → AAA, dns/dhcp/ntp/nas → server, pc/client, printer, phone). Set `icon` or
  `kind` when the guess is wrong.
- **Docs mismatch (when the generate step asks for one):** at most one `documented` value that differs from the
  gear: a device `documented.mgmt_ip`, an interface `documented.ip`/`vlan`, or an entity `documented.ip`/`mac`.
  Logs, configs and the capture keep the real value. Add `answer.doc_mismatch {ref, kind, note}`, with `ref` the
  row's `doc:<id>` (e.g. `doc:ACC-SW1-mgmt`, `doc:ise-a`, `doc:mac-pc-18`).
  - `red_herring`: the docs are stale, and the cause is elsewhere. The documented value appears in no log or config.
  - `cause`: someone configured what the docs said. The root cause's config diff `after` (or root event
    fields) must contain the documented value (D4).
  - Add a rubric item for it that cites the `doc:` row plus the log/config evidence showing the real value.

## Pattern catalog
Each pattern in `<repo>/scenarios/starter.yaml` carries `topic` (stp, trunk, acl, aaa, ntp, ospf, eigrp, bgp, fhrp,
port-security) and `cert` (`ENCOR`, `ENARSI` or `none`). `packetgen patterns` lists pattern ids and checks the
catalog first (filters: `--topic`, `--cert`, `--exclude ID...`; also `--file`, `--registry`). Exit 0 = ids printed,
1 = no match, 2 = catalog invalid (findings on stderr). `--show-capture ID` prints that pattern's capture hint.

## Fixing findings
| Check | Means | Fix |
|---|---|---|
| S0 | schema violation | match the schema; the message gives the JSON path |
| P1–P7 | catalog (all errors): unknown registry id / id not verified / header_style not renderable (ios, nxos, asa, bsd, meraki only) / topic or cert missing or invalid / duplicate pattern id / required key missing (id, symptom, root_cause, registry_ids, red_herrings, topic, cert) / P7 capture hint invalid (needs `kinds`, `evidence_kind`, `evidence`, `methods`; kinds in the flow catalog; evidence kind among them and with a symptom rule; methods a non-empty list of `span`/`erspan`) | fix the entry in `scenarios/starter.yaml`; use a verified, renderable registry id |
| R1–R5 | unknown id / unverified / missing or extra field / value breaks pattern / header style mismatch | see **log-formats** |
| T1–T4 | naive time / outside window / effect before cause / change after first symptom | use `Z` times; reorder |
| C1–C4 | root missing or doubled / chain can't reach root / noise has a parent / answer chain wrong | fix labels and `caused_by` |
| C5 | an id is used more than once across events, telemetry, config diffs and capture flows | give each its own id |
| S1–S4 | uneven points / error counter not rate or negative / CPU 5 min peak above 1 min / signal not visible | regenerate the series |
| E1–E2 | unknown device / undeclared MAC or IP | declare it in `topology` |
| K1–K4 | evidence ref unknown / duplicate rubric id / ref not rendered / a capture spec with no rubric item citing a symptom `pk` flow | point at real ids (`doc:<id>` rows count); add a rubric item about reading the frames |
| D1–D4 | more than one documented override / override and `answer.doc_mismatch` don't match up / `attached.device` not in topology / `kind: cause` but the documented value isn't in the root cause | keep one override, point `doc_mismatch.ref` at its row, attach to a real device, put the documented value in the root cause or use `red_herring` |
| L1 | a root-cause term leaks into id, brief, ticket text, a visible note, `capture.reason` or a flow string param | reword |
| N1 / Q1 | too little noise / root is the loudest line (warning) | add noise; quieter root evidence |
| TK1 | ticket names a device, IP or interface not in topology | name only known devices/addresses; an end_user shouldn't name gear at all; tokens like O365/M365, W10 or room numbers (B204) trip TK1, so spell them out (Office 365, Windows 10, room 204) |
| TK2 | end_user ticket quotes device output (show/traceroute/config) | describe what the user noticed |
| TK3 | misdirection claim under 4 words, or not found in the ticket text | plant a full sentence; copy it exactly |
| TK4 | no misdirection planted (warning) | plant one true-but-misleading statement |
| TK5 | ticket reuses 2+ word stems from `answer.fix`/`root_cause_terms` (warning); stems already in `meta.brief` or symptom-event fields do not count | describe the symptom, not the cause |
| PK0 | capture extra (dpkt) not installed | `pip install -e '.[capture]'` in the repo's venv |
| PK1 | capture device, peer or interface not in topology, the pair isn't linked, a device peer has no `peer_interface`, or an entity peer isn't attached to the monitored port | declare the device, interface and link; set the entity's `attached` |
| PK2 | capture start not before end, outside the window, or a flow plus its span doesn't fit | move the flow or widen the capture inside the window |
| PK3 | endpoint doesn't resolve or lacks the MAC/IP the kind needs, or an entity/interface MAC isn't a MAC or its IP isn't IPv4 (RADIUS client needs an entity with a MAC; DNS answer needs an IP) | declare it under `entities` or the device's `interfaces[]` |
| PK4 | flow params break the kind's schema, gratuitous ARP with dst != src, DNS ok without answer, or AAAA ok | fix the params; AAAA answers are unsupported |
| PK5 | symptom on a kind with no symptom rule; an `arp` symptom that is neither the port-security violator nor an unanswered request on a VLAN the peer pruned; an `stp_bpdu`/`dhcp`/`cdp`/`hsrp_hello` symptom without its log or config evidence (bpdufilter edit / no-free-leases or violation / NATIVE_VLAN_MISMATCH / matching STATECHANGE); or a RADIUS flow whose outcome disagrees with the RADIUS_DEAD/ALIVE log events | label it noise or use `radius_request`; no_response: put it inside a dead period (DEAD at most 30 s after the request, or earlier with no ALIVE between); accept/reject: move it outside DEAD <= t < next ALIVE; a symptom flow caused by the DEAD event can't start before it (T3), so the 30 s lead needs an earlier cause |
| PK6 | tshark missing or older than 4.2, a filter/dump failure, malformed or expert-error frames, a symptom flow whose expected filter matches none of its frames; a warning "the tshark read-back was skipped" under `--no-tshark` | install tshark 4.2+; fix the flow params; rebuild without `--no-tshark` before handing out |
| PK7 | capture over 5,000 frames | shorten `start..end` or lower `noise` |
| PK8 | a symptom flow the capture method can't see, or one after the monitored port's err-disable | pick a method that sees it (replicate for BPDUs/CDP); move the flow before the err-disable |
| PK9 | `reason` doesn't name `capture.device`; a flow VLAN not native and not in `trunk_vlans`; ERSPAN analyzer not an entity with mac+ip, `origin_ip` not on `device`, or `via` unresolved | fix the reason or the method block |
| X1, Z1, Z2, B1 | xlsx date cell / non-doc IP / non-doc MAC / packet exists | build-side; B1 needs `--force` |
