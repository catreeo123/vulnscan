# ADR 0003 — Claude Code Skill Self-Registration via `vulnscan skill install`

**Date:** 2026-05-27  
**Status:** Accepted

---

## Context

vulnscan ships a Claude Code skill (`/vulnscan`) that runs a Scan, parses JSON output, and reports Findings with severity, fix guidance, and breaking-change signals. The skill lives as `SKILL.md` in `~/.claude/skills/vulnscan/`.

Users who install vulnscan via npm need a way to register this skill in their Claude Code setup. Three options were evaluated:

1. **Manual copy** — document the path in README; user copies the file themselves
2. **Separate CLI tool** — a dedicated skill manager (e.g. `skill-cli`) that installs any skill
3. **`vulnscan skill install`** — vulnscan self-registers its own skill

## Decision

**Option 3: `vulnscan skill install`**, following the pattern established by `graphify install`.

## Rationale

**Against option 1 (manual copy):** Requires the user to know where the installed package's `SKILL.md` lives, which varies by package manager and OS. Breaks on package updates — user must re-copy manually.

**Against option 2 (separate tool):** A general skill manager is a different product with broader scope. Builds a dependency on infrastructure that does not exist. Adds install friction — two tools instead of one.

**For option 3:** Single `npm install -g @catreeo123/vulnscan && vulnscan skill install` flow covers the entire setup. `skill/` directory ships with the package (added to `files` in `package.json`), so the source is always co-located with the version the user installed. Idempotent — safe to re-run after upgrades.

The `skill` subcommand namespace is intentional: it leaves room for `vulnscan skill update` and `vulnscan skill uninstall` if needed, without polluting the top-level command surface.

## Consequences

- `skill/SKILL.md` must be kept up-to-date with the behavior of `vulnscan scan --format json`
- `vulnscan skill install` does not patch `~/.claude/CLAUDE.md` — Claude Code discovers skills from the skills directory automatically
- If `~/.claude/` does not exist, the command creates it and warns the user to install Claude Code
