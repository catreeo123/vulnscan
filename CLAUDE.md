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
scan:  lockfile-parser → syncIfStale → AdvisoryStore.getForPackage
                                           → matchAffected → deduplicate → renderGrouped/renderJson

check: syncIfStale → AdvisoryStore.getForPackage → matchAffected → deduplicate → render

update: runSync (full re-sync, no staleness check)
```

**Module responsibilities:**

| Module | Role |
|--------|------|
| `cli.ts` | Entry point. Exports `run(argv: string[]): Promise<number>` — returns exit code, never calls `process.exit()` inline (preserves stdout flush). Module-level wrapper sets `process.exitCode`. `computeExitCode()` implements the exit code matrix |
| `cli-args.ts` | Parses `process.argv` into `ParsedArgs`. `--offline`/`--no-sync` → `noSync: boolean` |
| `scanner.ts` | `runScan()` / `checkPackage()` — orchestrates parse → sync → match → deduplicate. Skips local/git deps. Both accept `sync?: SyncFn` for test injection; production default is `syncIfStale` |
| `lockfile-parser.ts` | Parses `package-lock.json` into `Dep[]`, delegating entry resolution to `lockfile-resolver.ts` |
| `lockfile-resolver.ts` | `resolveEntry()` — classifies each lockfile entry as plain/workspace/alias/git dep |
| `sync-orchestrator.ts` | `syncIfStale()` — per-source staleness check with clock-skew detection and double-check guard; returns `ScanWarning[]`. `runSync()` forces full pull |
| `osv-sync.ts` | Fetches OSV zip bulk download, upserts advisories, returns `{ fullSyncStartedAt, warnings }` |
| `github-advisory-sync.ts` | Two-pass pagination of GitHub Advisory API (reviewed + malware); returns `{ imported, skipped, warnings }`. Sets `hitPageLimit` flag to prevent cursor advance on truncation |
| `advisory-store-sqlite.ts` | `SqliteAdvisoryStore` — production `AdvisoryStore` backed by `better-sqlite3`. `openStore()` is the entry point |
| `advisory-store-memory.ts` | `InMemoryAdvisoryStore` — in-memory `AdvisoryStore` used in unit tests |
| `local-db.ts` | Raw SQLite helpers. Schema migrations run inline in `openDb()`. `safeAddColumn()` tolerates concurrent `ALTER TABLE` races on WAL-mode DB |
| `affected-range-matcher.ts` | Semver range matching for `{ name, version }` against advisory ranges |
| `deduplicator.ts` | Deduplicates findings by `canonical_id` (GHSA ID preferred) |
| `output-renderer.ts` | `renderGrouped()` (table) and `renderJson()`. JSON output includes `schemaVersion: '1'` as first key |
| `severity-mapper.ts` | `mapSeverity({ label?, advisoryId })` — maps OSV severity strings to `Severity`; fails safe to `'high'` |
| `warnings.ts` | `ScanWarning` type (`incomplete` \| `informational`), factory functions `incomplete()` / `informational()`, `hasIncomplete()` predicate |
| `config.ts` | `.vulnscanrc` loader (project dir then `~`), validates `failOn` and `stalenessHours`. `Config` includes `stalenessMs` (computed from `stalenessHours` at load time — callers use `config.stalenessMs` directly) |
| `secrets.ts` | Scrubs tokens/keys from error messages before writing to stderr |
| `bootstrap.ts` | `maybeBootstrap()` — downloads pre-built `db.sqlite.gz` from GitHub Releases on first run |
| `skill-installer.ts` | `installSkill({ claudeDir?, sourcePath? })` — copies `skill/SKILL.md` to `~/.claude/skills/vulnscan/`; used by `vulnscan skill install` |
| `ancestry.ts` | Resolves transitive dependency ancestry from lockfile |
| `types.ts` | Shared types: `Advisory`, `AdvisoryStore`, `Finding`, `Severity`, `SemverRange`, `Dep` |

**AdvisoryStore seam:**

`AdvisoryStore` (defined in `types.ts`) is the interface between sync/scan logic and the underlying storage. Production code uses `SqliteAdvisoryStore`; tests use `InMemoryAdvisoryStore` or hand-rolled mocks. All sync and scan functions accept `AdvisoryStore`, never a raw `Database` handle.

## Exit Code Matrix

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above `failOn` threshold, no incomplete warnings |
| `1` | Findings — at least one finding meets the `failOn` severity threshold |
| `2` | Incomplete — at least one `incomplete` warning (data may be missing); takes priority over code `1` |

`computeExitCode()` in `cli.ts` implements this precedence: incomplete > findings > clean.

## Database

SQLite at `~/.vulnscan/db.sqlite` (override: `VULNSCAN_DB_PATH`). WAL mode, `busy_timeout = 5000ms`.

Schema migrations run inline in `openDb()` — no migration files. `safeAddColumn()` tolerates concurrent `ALTER TABLE` races. Columns `synced_at`, `last_seen_in_full_sync`, and `canonical_id` were added post-initial-schema; `canonical_id` backfill runs in `openDb()` on first open.

Primary key on `advisories` is `(id, package_name)` — the same GHSA advisory can cover multiple packages.

`pruneStaleAdvisories()` removes OSV advisories not seen in the last full sync (plus a 7-day grace period). GitHub advisories are never pruned (`last_seen_in_full_sync = now` on every upsert).

Results from `getAdvisoriesForPackage` are ordered `canonical_id ASC, id ASC` for deterministic output.

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

Tests co-located with source (`src/foo.test.ts`). E2E tests in `src/cli.e2e.test.ts` — spawn CLI as subprocess against a temp DB and real lockfile fixtures. Unit tests use `vi.mock` for HTTP; **do not `vi.mock` sync-orchestrator** — inject a stub via `sync:` on `ScanInput`/`CheckInput` instead:

```typescript
const syncStub = vi.fn().mockResolvedValue([])
await runScan({ lockfileContent, store, config: baseConfig, sync: syncStub })
expect(syncStub).toHaveBeenCalledWith(store, baseConfig.stalenessMs)
```

**`vi.spyOn(process.stderr, 'write')` is unreliable in vitest ESM.** Use direct property replacement instead:

```typescript
const written: string[] = []
const origWrite = process.stderr.write.bind(process.stderr)
;(process.stderr as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
// ... run code ...
;(process.stderr as any).write = origWrite
```

## Versioning

After every fix or feature: bump `version` in `package.json` before committing.

| Change type | Bump |
|-------------|------|
| Bug fix, refactor, docs | patch (`0.1.0` → `0.1.1`) |
| New feature, new flag, new command | minor (`0.1.0` → `0.2.0`) |
| Breaking CLI or JSON output change | major (`0.1.0` → `1.0.0`) |

Update `CHANGELOG.md` with a matching entry under the new version heading.

## Deferred Work

Open issues tracked in GitHub Issues (`catreeo123/vulnscan`). As of v0.1.0 + #18, all implementation issues are shipped. Remaining deferred: #09 (SQLite PRAGMA tuning — `journal_size_limit`, `cache_size`, `mmap_size`).

## AI Integration

- **JSON output schema** — `docs/output-schema.md`. Full field reference for `--format json` output. Read before parsing or building any consumer of vulnscan's JSON.
- **Claude Code Skill contract** — `.claude/skill-contract.md`. Specifies the `/vulnscan` skill: input, output format, edge cases, and the decisions behind each behavior. Read before modifying skill behavior or the JSON output schema.
- **Skill source** — `skill/SKILL.md` ships with the package. `vulnscan skill install` copies it to `~/.claude/skills/vulnscan/`. Keep in sync with the JSON output schema and skill contract.

## Agent skills

### Issue tracker

Issues live in GitHub Issues (`catreeo123/vulnscan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context repo — `CONTEXT.md` at root, ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

**HARD STOP: Read graphify-out/GRAPH_REPORT.md FIRST — before any file read, grep, glob, or codebase question. No exceptions. "I already know the codebase" is not a valid reason to skip it.**

What to extract from GRAPH_REPORT.md before proceeding:
1. **God nodes** — highest-edge nodes = highest blast radius. Touch these last, test these most.
2. **Cross-community bridges** — nodes with high betweenness centrality = bug propagation highways.
3. **Knowledge gaps / isolated nodes** — weakly-connected nodes = undocumented or undertested. Directly predicts coverage gaps.
4. **Graph freshness** — check `Built from commit` vs `git rev-parse HEAD`. If stale, run `graphify update .` before reading anything else.

Additional rules:
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` in the same session (AST-only, no API cost, takes ~5s)
