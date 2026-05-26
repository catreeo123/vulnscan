# Issue #12 — Claude Code Skill: `/vulnscan`

**Status:** Active (ready for implementation)  
**Origin:** AI-friendly initiative (grill session, 2026-05-27)  
**Contract:** `.claude/skill-contract.md`  
**Schema ref:** `docs/output-schema.md`

---

## Problem Statement

vulnscan produces machine-readable JSON output, but a developer using Claude Code must still manually run the CLI, read raw JSON, cross-reference advisory URLs, and assess upgrade risk themselves. There is no first-class path from "I want to know if my project is vulnerable" to "I understand what is wrong, what to upgrade, and whether upgrading is safe."

## Solution

A Claude Code Skill (`/vulnscan`) that runs a Scan against a target directory, parses the JSON output, and delivers a contextual advisory report inside the Claude Code session — explaining each Finding, surfacing the fix version, and flagging breaking upgrade risk.

## User Stories

1. As a developer, I want to type `/vulnscan` in Claude Code and get a plain-language summary of my project's vulnerabilities, so that I don't have to read raw JSON or visit advisory URLs manually.
2. As a developer, I want to pass an optional path to `/vulnscan`, so that I can scan a project that is not my current working directory.
3. As a developer, I want each Finding explained with its severity and what the vulnerability actually does, so that I can triage which issues to fix first.
4. As a developer, I want to know the safe upgrade version for each vulnerable package, so that I know exactly what to change in my lockfile.
5. As a developer, I want a clear warning when the safe upgrade is a major version bump, so that I can anticipate breaking changes before I upgrade.
6. As a developer, I want a plain statement when no fix is available, so that I know I need to consider removing or replacing the package rather than upgrading.
7. As a developer, I want malicious package findings (`MAL-*`) distinguished from CVE vulnerabilities, so that I understand when the threat is a supply chain attack rather than a code vulnerability.
8. As a developer, I want sync warnings surfaced before findings, so that I know if any packages were skipped (e.g. git-sourced deps) and why.
9. As a developer, I want a clear error if `vulnscan` is not installed, with the exact installation command, so that I can fix the prerequisite without hunting for docs.
10. As a developer, I want a clear error if `package-lock.json` is missing, so that I understand the scan requires a lockfile.
11. As a developer, I want zero findings to be stated clearly with the count of packages scanned, so that I have confidence the scan actually ran.
12. As a CI author, I want the skill to work without me configuring anything beyond installing vulnscan, so that there is no friction to adoption.
13. As a security-aware developer, I want each finding to include the canonical advisory URL, so that I can read the full CVE or GHSA record if I need more context.

## Implementation Decisions

### Module: Skill file

Single file: `.claude/skills/vulnscan.md`. This is the complete implementation — a skill invocation file that Claude Code loads when `/vulnscan` is typed. No compiled code, no new dependencies.

### Input handling

- Invoked as `/vulnscan` (cwd) or `/vulnscan <path>` (explicit target)
- Runs: `vulnscan scan <path> --format json`
- On missing `vulnscan` binary: surface installation instructions, stop
- On missing `package-lock.json`: surface the error from vulnscan, stop

### Output structure

1. Warnings block (if any) — list non-fatal notices first
2. Zero-findings confirmation (if clean) — state package count scanned
3. Findings grouped by severity (critical → high → moderate → low)
4. Per finding: package identity, advisory ID + title, type signal, fix or no-fix statement, advisory URL

### Malicious package signal

`advisory.type === 'mal'` findings receive a distinct heading — "Malicious Package" — not just a severity label. Supply chain attacks are categorically different from CVE vulnerabilities and must be visually distinct.

### Breaking change detection

Semver major comparison only: `major(fix) > major(installed version)` → flag "likely breaking changes". No title heuristics. Deterministic, no hallucination risk.

### No-fix message

Exact wording: "No fix available. Consider removing or replacing this package." Do not suggest specific alternative packages — advisory data does not contain this and inference would hallucinate.

### Schema contract

Parses JSON per `docs/output-schema.md`. Skill must not hardcode field assumptions — read schema doc before implementation to stay in sync with actual output shape.

## Testing Decisions

Good tests for this skill verify **observable behavior** — what the user sees — not internal parsing logic.

### What makes a good test

- Run `/vulnscan` against a fixture project with known vulnerable packages; assert the output contains the expected package name, advisory ID, fix version, and breaking change warning
- Run `/vulnscan` against a clean project; assert "no findings" message appears
- Run `/vulnscan` in a directory without `package-lock.json`; assert the error message is surfaced
- Run with a `MAL-*` finding in the output; assert the "Malicious Package" label appears

### Prior art

`src/cli.e2e.test.ts` — spawns the CLI as a subprocess against a temp DB and fixture lockfiles. The skill tests would follow the same pattern: fixture lockfile + controlled DB state + assert on text output.

### Modules to test

- The skill file itself via manual invocation in Claude Code (smoke test)
- E2E: fixture with known vulnerable package → assert finding appears with correct fields

## Out of Scope

- Severity filtering in the skill (use `--fail-on` on the CLI directly)
- Automatic upgrade execution (skill advises, developer acts)
- `yarn.lock` / `pnpm-lock.yaml` support (blocked on lockfile parser v2)
- Fetching full advisory text from canonical URLs (title in JSON is sufficient)
- `vulnscan check` via the skill (single-package lookup is a separate workflow)

## Further Notes

The full contract (input/output/edge cases/decisions) is in `.claude/skill-contract.md`. Implementation should read that doc first — it captures the rationale behind each decision so future sessions don't re-litigate them.

The JSON output shape is documented in `docs/output-schema.md` with field-level descriptions and a worked example. Skill implementation must read this before parsing — do not infer the schema from README or source code.
