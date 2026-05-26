# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm test                                    # run all tests (vitest run)
npm run test:watch                          # vitest watch mode
npx vitest run src/scanner.test.ts          # single test file
npx vitest run src/scanner.test.ts -t "name" # single test by name
npm run build                               # tsc → dist/
```

No lint script is configured. TypeScript strict mode catches most issues at build time.

## Architecture

`vulnscan` is a CLI tool that scans `package-lock.json` for npm vulnerabilities using a local SQLite advisory database synced from OSV and GitHub Advisory Database.

**Data flow:**

```
cli.ts → parseArgs → [scan | check | update | help]
                         ↓
scan:  lockfile-parser → syncIfStale → getAdvisoriesForPackage
                                           → matchAffected → deduplicate → renderGrouped/renderJson

check: syncIfStale → getAdvisoriesForPackage → matchAffected → deduplicate → render

update: runSync (full re-sync, no staleness check)
```

**Module responsibilities:**

| Module | Role |
|--------|------|
| `cli.ts` | Entry point. Routes commands, owns `db` lifecycle (open/close in `finally`) |
| `cli-args.ts` | Parses `process.argv` into `ParsedArgs` |
| `scanner.ts` | `runScan()` — orchestrates parse → sync → match → deduplicate |
| `lockfile-parser.ts` | Parses `package-lock.json` into `{ name, version }[]` |
| `sync-orchestrator.ts` | `syncIfStale()` checks staleness per-source; `runSync()` forces full pull |
| `osv-sync.ts` | Fetches OSV zip bulk download, upserts advisories |
| `github-advisory-sync.ts` | Paginates GitHub Advisory API (`/advisories?ecosystem=npm`) |
| `local-db.ts` | SQLite via `better-sqlite3`. Schema migrations run in `openDb()` |
| `affected-range-matcher.ts` | Semver range matching for `{ name, version }` against advisory ranges |
| `deduplicator.ts` | Deduplicates findings by `canonical_id` (GHSA ID preferred) |
| `output-renderer.ts` | `renderGrouped()` (table) and `renderJson()` |
| `config.ts` | `.vulnscanrc` loader (project dir then `~`), validates `failOn` and `stalenessHours` |
| `secrets.ts` | Scrubs tokens/keys from error messages before writing to stderr |
| `ancestry.ts` | Resolves transitive dependency ancestry from lockfile |
| `types.ts` | Shared types: `Advisory`, `Finding`, `Severity`, `SemverRange` |

## Database

SQLite at `~/.vulnscan/db.sqlite` (override: `VULNSCAN_DB_PATH`).

Schema migrations run inline in `openDb()` — no migration files. `safeAddColumn()` tolerates concurrent `ALTER TABLE` races on WAL-mode DB. Both `advisories` columns `synced_at`, `last_seen_in_full_sync`, and `canonical_id` were added post-initial-schema; the backfill for `canonical_id` runs in `openDb()` on first open.

Primary key on `advisories` is `(id, package_name)` — the same GHSA advisory can cover multiple packages.

`pruneStaleAdvisories()` removes OSV advisories not seen in the last full sync (plus a 7-day grace period). GitHub advisories set `last_seen_in_full_sync = now` on every upsert so they are never pruned.

## Configuration

`.vulnscanrc` (JSON) searched at `<projectDir>/.vulnscanrc` then `~/.vulnscanrc`:

```json
{
  "failOn": ["critical", "high"],
  "stalenessHours": 24
}
```

CLI `--fail-on` overrides config. Invalid severities warn to stderr and fall back to defaults.

## Environment Variables

| Variable | Effect |
|----------|--------|
| `VULNSCAN_DB_PATH` | Override SQLite path |
| `GITHUB_TOKEN` | Auth for GitHub Advisory API — without it, rate-limited to 60 req/hr |
| `VULNSCAN_NO_BOOTSTRAP` | Skip release DB download on first run; fall straight to full OSV sync |

## Test Layout

Tests co-located with source (`src/foo.test.ts`). E2E tests in `src/cli.e2e.test.ts` — these spawn the CLI as a subprocess against a temp DB and real lockfile fixtures. Unit tests use vitest mocks (`vi.mock`) for HTTP and DB.

## Deferred Work

Open issues tracked in `.claude/issues/INDEX.md`. Active (ready for pickup): #10 (AdvisoryStore pilot), #12 (Claude Code Skill). Deferred: #09 (SQLite PRAGMA tuning), #11 (AdvisorySource seam). Issues #01–#08 are shipped.

## AI Integration

- **JSON output schema** — `docs/output-schema.md`. Full field reference for `--format json` output. Read before parsing or building any consumer of vulnscan's JSON.
- **Claude Code Skill contract** — `.claude/skill-contract.md`. Specifies the `/vulnscan` skill: input, output format, edge cases, and the decisions behind each behavior. Read before implementing issue #12.

## Agent skills

### Issue tracker

Issues live in GitHub Issues (`catreeo123/vulnscan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context repo — `CONTEXT.md` at root, ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
