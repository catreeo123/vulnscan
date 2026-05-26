# Issue #12c — Error cases

## Parent

[#12 — Claude Code Skill `/vulnscan`](12-claude-code-skill.md)

## What to build

Extend the skill file from #12a to handle two prerequisite failure cases gracefully, so the developer gets actionable guidance instead of a raw shell error.

1. **`vulnscan` not on PATH** — before scanning, check whether `vulnscan` is available. If not: tell the user to run `npm install && npm run build && npm link` in the vulnscan repo, then stop. Do not attempt to scan.

2. **`package-lock.json` missing** — if vulnscan exits with an error about a missing lockfile, surface that error message clearly and stop. Do not attempt to explain it further.

## Acceptance criteria

- [ ] Invoking `/vulnscan` in a directory without `vulnscan` on PATH shows the installation command and stops
- [ ] Invoking `/vulnscan` in a directory without `package-lock.json` shows the error from vulnscan and stops
- [ ] Neither error case produces a raw stack trace or JSON parse error
- [ ] Happy-path behavior from #12a is unaffected

## Blocked by

- [#12a — Skill scaffold](12a-skill-scaffold.md)
