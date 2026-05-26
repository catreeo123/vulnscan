# Issue #12a — Skill scaffold: core happy path

## Parent

[#12 — Claude Code Skill `/vulnscan`](12-claude-code-skill.md)

## What to build

Create `.claude/skills/vulnscan.md` — the skill invocation file Claude Code loads when `/vulnscan` is typed.

Core behavior:
- Accept optional `<path>` argument; default to cwd
- Run `vulnscan scan <path> --format json`
- Parse the JSON output per `docs/output-schema.md`
- Group findings by severity (critical → high → moderate → low)
- Per finding: `name@version` (plus `via <dep>` if present), advisory ID + title, fix version, advisory URL
- Zero findings: state clearly that no vulnerabilities were found

Full output contract in `.claude/skill-contract.md`.

## Acceptance criteria

- [ ] `/vulnscan` (no args) runs against cwd and displays findings
- [ ] `/vulnscan <path>` runs against the given path
- [ ] Findings are grouped critical → high → moderate → low
- [ ] Each finding shows: package identity, advisory ID + title, fix version, advisory URL
- [ ] Transitive dep findings show `via <direct-dep>`
- [ ] Zero findings produces a clear "no vulnerabilities" confirmation
- [ ] Output is readable plain-language prose, not raw JSON

## Blocked by

None — can start immediately.
