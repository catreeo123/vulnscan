# Issue #12b — Signal enrichment

## Parent

[#12 — Claude Code Skill `/vulnscan`](12-claude-code-skill.md)

## What to build

Extend the skill file from #12a with four additional output signals:

1. **Breaking change warning** — when `fix` major version > installed major version, append "⚠ major version bump — likely breaking changes" to the fix line. Semver major comparison only; no title heuristics.

2. **Malicious package heading** — when `advisory.type === 'mal'`, replace the severity group label with "Malicious Package" heading. Supply chain attacks must be visually distinct from CVE vulnerabilities.

3. **No-fix statement** — when `fix` is undefined, show exactly: "No fix available. Consider removing or replacing this package."

4. **Warnings block** — if `warnings` array is non-empty, list all warnings under a "Warnings" heading before findings.

## Acceptance criteria

- [ ] Fix version with major bump shows "⚠ major version bump — likely breaking changes"
- [ ] Fix version without major bump shows no breaking change warning
- [ ] `fix: undefined` shows exact wording "No fix available. Consider removing or replacing this package."
- [ ] `advisory.type === 'mal'` findings show "Malicious Package" heading, not a severity label
- [ ] Non-empty `warnings` array is listed before findings under "Warnings" heading
- [ ] Empty `warnings` array produces no warnings section

## Blocked by

- [#12a — Skill scaffold](12a-skill-scaffold.md)
