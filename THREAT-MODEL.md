# Threat model

Short and honest; revisit before the first public push and whenever a new input source is added.

## Assets
- **The output directory.** Packets and keys are written under the configured output directory. A bad path
  or overwrite could clobber notes.
- **Answer keys** (`Keys/` under the output directory). Low sensitivity, but leaking them spoils practice.
- **The public repo's history.** Anything committed is permanent; real IPs/MACs/hostnames must never land.

## Who or what could cause harm
- **A contributor PR to `registry/` or `scenarios/`** that plants real IPs, MACs or hostnames, or
  instruction-like text aimed at the model that reads it.
- **The generating model itself** (Claude writes the scenario spec): it can invent log formats,
  produce internally inconsistent evidence, or leak the answer into the brief.

## Trust boundaries and controls
| Boundary | Control |
|---|---|
| Registry/scenario text → model context | Treated as data, never instructions (stated in every SKILL.md). |
| Model-written spec → files on disk | `validate()` must return zero errors; rendering happens in a temp dir and moves into the output directory only after post-render checks pass. |
| Repo → public GitHub | `scripts/pre-commit` sanitize gate (checks Z1-Z5: RFC 5737/1918 IPs, RFC 7042 MACs only, no home paths, local deny terms); CI `permissions: contents: read`, pinned actions. |
| Build → tshark | tshark is an external GPL program run with a fixed argv on files we generated. Spec text never reaches the filter or argv: display filters come from catalog constants in code. |
| Build → existing packets | Refuses to overwrite an existing packet folder unless `--force`. |

## Accepted risks (dated)
- **2026-10-22:** Generated packets are synthetic. Log formats are verified against vendor docs,
  source code or parser fixtures, not captured from gear. Mitigation: `verified` flag per format;
  README states it; gear captures replace entries over time.
- **2026-11-02:** CI installs the newest dependency versions allowed by `pyproject.toml` (no lockfile), so a new upstream release can change CI results without a repo change.
- **2026-11-04:** Captures are synthetic and not gear-validated: frames come from a renderer, not from a
  real SPAN port. Mitigation: tshark read-back (dissectors must agree with the renderer, and its dump goes
  through the sanitize gate) and a README statement.
