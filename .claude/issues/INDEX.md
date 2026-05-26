# Issues — security-scan-cli

Generated from `post-tier4-synthesis.md` + post-Group-1 code-review. Each file is one tracer-bullet slice that cuts end-to-end through schema/persistence/CLI/tests where applicable.

## Active (decision made, ready for implementation)

| # | Title | Decision | Origin |
|---|-------|----------|--------|
| 10 | [AdvisoryStore repository pilot](10-advisory-store-pilot.md) | run pilot (2-3 test conversions + ADR) | A2 |
| 12 | [Claude Code Skill `/vulnscan`](12-claude-code-skill.md) | PRD — see sub-issues below | AI-friendly initiative |
| 12a | [Skill scaffold: core happy path](12a-skill-scaffold.md) | create skill file, happy path | AI-friendly initiative |
| 12b | [Signal enrichment](12b-signal-enrichment.md) | breaking change + MAL + no-fix + warnings (blocked by 12a) | AI-friendly initiative |
| 12c | [Error cases](12c-error-cases.md) | missing binary + missing lockfile (blocked by 12a) | AI-friendly initiative |

## Deferred (HITL — decision recorded as defer)

| # | Title | Decision | Origin |
|---|-------|----------|--------|
| 09 | [SQLite PRAGMA tuning](09-sqlite-pragma-tuning.md) | defer — no perf complaint yet; revisit on real bottleneck | N7 |
| 11 | [AdvisorySource seam](11-advisory-source-seam.md) | defer — gated on third-source driver appearing on roadmap | A1 |

## Closed (shipped)

| # | Title | Commit |
|---|-------|--------|
| 07 | JSON renderer surfaces warnings | `731a725` |
| 08 | Scope `-h` / `--help` to subcommands | `731a725` |
| 01 | Extract `checkPackage` into scanner.ts | `f8d98d3` |
| 02 | Add summary line to `check` command output | `f8d98d3` |
| 03 | Preserve 401/403 status in `fetchWithRetry` final-attempt error | `af857a1` |
| 04 | `onProgress` callback contract relabel (parsed/total) | `af857a1` |
| 05 | Conditional `chmodSync`: skip when perms already 0o600 | `af857a1` |
| 06 | Consume final-attempt 429 response body before throwing | `af857a1` |

Post-review tightening landed in `45ac58a` (per-retry body cancel + 4 test pin-ups).

## Origin keys

- `A*` — architecture review (post-tier4-synthesis Group 2)
- `B*`, `M*`, `N*` — scrutinize findings
- `F*` — extra-high-recall code-review findings (post-Group-1)
- AI-friendly initiative — grill session 2026-05-27 (output schema, skill contract, Claude Code Skill)
