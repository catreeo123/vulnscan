# vulnscan — Architecture Overview

> Written for someone who thought this was a simple CLI and discovered it isn't. It isn't simple, but every piece has a reason. This doc explains what the pieces are, why they exist, and how they connect.

---

## The one-sentence version

vulnscan downloads vulnerability data from two upstream databases into a local SQLite file, then scans your `package-lock.json` against that local copy. Nothing happens live at scan time — it's a local lookup, not a network call.

---

## Why a local database?

The obvious design is: run `vulnscan scan`, hit the npm advisory API, get results back. Simple. But:

- **npm Advisory has lag.** Vulnerabilities appear on GitHub Advisory and OSV days to weeks before npm mirrors them. vulnscan skips npm entirely.
- **Scan speed.** A local SQLite lookup is sub-second. An API call is not.
- **Offline use.** CI pipelines that block outbound traffic still work once the DB is seeded.

The tradeoff: you must keep the local DB fresh. vulnscan automates this with the **Sync** system.

---

## The two data sources

```
OSV (Google)                          GitHub Advisory Database
─────────────────────────────────     ──────────────────────────────────────
Downloads a single ZIP (~200MB)       Paginates a REST API (/advisories)
Contains ALL npm CVEs + MAL-* entries Contains additional npm CVE coverage
One request per sync                  Many requests; rate-limited without token
No auth required                      No auth required (60 req/hr); faster with
                                      GITHUB_TOKEN (5000 req/hr)
```

OSV covers both regular vulnerabilities (`CVE-*`) and supply chain signals (`MAL-*` — malicious packages detected by OpenSSF). GitHub Advisory provides additional CVE coverage for the npm ecosystem, often catching issues before they propagate elsewhere.

Both sources write into the same SQLite `advisories` table. They share a primary key structure, and the **deduplicator** merges Findings from both sources that describe the same vulnerability (same package + CVE ID).

---

## System diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        User CLI call                        │
│                  e.g. vulnscan scan ./                      │
└────────────────────────────┬────────────────────────────────┘
                             │
                        cli.ts
                  parseArgs → route command
                             │
              ┌──────────────┼──────────────┐
              │              │              │
           scan           check          update
              │              │              │
         scanner.ts      scanner.ts    sync-orchestrator.ts
         runScan()       checkPackage()  runSync() ← forces full
              │              │
    ┌─────────▼──────────────▼──────────┐
    │         syncIfStale()             │  ← only if DB is stale
    │       sync-orchestrator.ts        │     (default: > 24 hours)
    └─────┬──────────────────────┬──────┘
          │                      │
     osv-sync.ts       github-advisory-sync.ts
     (ZIP download)    (paginated REST API)
          │                      │
          └──────────┬───────────┘
                     │
              AdvisoryStore
          (advisory-store-sqlite.ts)
                     │
              local-db.ts
           (SQLite at ~/.vulnscan/db.sqlite)
                     │
    ┌────────────────▼────────────────────┐
    │  advisories table                   │
    │  id, package_name, severity,        │
    │  affected_ranges, canonical_id ...  │
    └────────────────┬────────────────────┘
                     │
    ┌────────────────▼────────────────────┐
    │  affected-range-matcher.ts          │
    │  semver range check per dep         │
    └────────────────┬────────────────────┘
                     │
    ┌────────────────▼────────────────────┐
    │  deduplicator.ts                    │
    │  merge same vuln from both sources  │
    └────────────────┬────────────────────┘
                     │
    ┌────────────────▼────────────────────┐
    │  output-renderer.ts                 │
    │  table (default) or JSON            │
    └─────────────────────────────────────┘
```

---

## The staleness system

Every sync records a timestamp per source in the DB. Before a scan, `syncIfStale()` checks:

1. When did OSV last sync? When did GitHub Advisory last sync?
2. Is either older than `stalenessHours` (default: 24h, configurable)?
3. If yes: sync that source. If no: skip it.

This means a scan is usually instant. The sync only runs when the data is old.

There's a **clock-skew guard**: after syncing, `syncIfStale()` re-reads the timestamps to verify the write landed. This protects against two vulnscan processes running simultaneously and both thinking they need to sync.

---

## The bootstrap system

First-ever run: there's no DB file. A full sync from scratch (OSV ZIP + GitHub pagination) can take minutes. That's a bad first-run experience.

**Bootstrap** solves this by downloading a pre-built compressed DB snapshot (`db.sqlite.gz`) from the latest GitHub Release. This seeds the DB in seconds. After bootstrap, the normal staleness check applies.

```
First run:
  ~/.vulnscan/db.sqlite doesn't exist
         ↓
  bootstrap.ts: download db.sqlite.gz from GitHub Releases
         ↓
  decompress to ~/.vulnscan/db.sqlite
         ↓
  proceed to scan (DB exists, staleness check runs normally)

If bootstrap fails → fall back to full sync from OSV + GitHub
If VULNSCAN_NO_BOOTSTRAP set → skip to full sync immediately
```

---

## The AdvisoryStore seam

`AdvisoryStore` is an interface (defined in `types.ts`) that abstracts all DB operations:

```typescript
interface AdvisoryStore {
  getForPackage(name: string): Advisory[]
  upsert(advisory: Advisory): void
  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void
  count(): number
  pruneStale(fullSyncStartedAt: number, gracePeriodMs: number): void
  getLastSyncedAt(source: string): number | null
  setLastSyncedAt(source: string, ts: number): void
  close(): void
}
```

Two adapters implement it:

| Adapter | Where used | Backed by |
|---------|-----------|-----------|
| `SqliteAdvisoryStore` | Production | `local-db.ts` + SQLite on disk |
| `InMemoryAdvisoryStore` | Tests | Plain in-memory Map, zero I/O |

**Why this seam exists:** Before it existed, every test that touched the scan or sync layer needed to create a real SQLite file in a temp directory, then delete it in `afterEach`. That's a lot of boilerplate and slow I/O. The `InMemoryAdvisoryStore` makes tests fast and stateless.

---

## The scan pipeline in detail

```
package-lock.json
      ↓
lockfile-parser.ts → lockfile-resolver.ts
  Parses the lock file into Dep[] (name + version pairs)
  Skips: git-sourced deps, npm-aliased deps (can't semver-match these)
  These skipped deps emit a ScanWarning (informational)
      ↓
syncIfStale()   ← skipped if --offline / --no-sync
      ↓
For each Dep:
  AdvisoryStore.getForPackage(name)
  → affected-range-matcher.ts: does this version fall in any advisory's range?
  → collect Findings
      ↓
deduplicator.ts
  Same vuln from OSV + GitHub Advisory → keep highest severity, prefer GHSA id
      ↓
output-renderer.ts
  --format json  → renderJson()  (includes schemaVersion: '1')
  default        → renderGrouped() (table grouped by package)
      ↓
cli.ts: computeExitCode()
  0 = clean
  1 = findings at/above --fail-on threshold
  2 = incomplete warnings (data might be missing) — takes priority over 1
```

---

## The warning system

Two warning classes flow through the pipeline:

| Class | Meaning | Exit code impact |
|-------|---------|-----------------|
| `incomplete` | Data might be missing — a sync source failed, rate-limited, etc. | **Causes exit 2** (takes priority over findings) |
| `informational` | Something was skipped but results are still complete — git dep, alias dep | No exit code impact |

Warnings are emitted in the sync layer (`osv-sync.ts`, `github-advisory-sync.ts`, `sync-orchestrator.ts`), collected in `scanner.ts` as `ScanResult.warnings`, rendered by `output-renderer.ts`, and tested by `cli.ts` via `hasIncomplete()` before deciding the exit code.

The key design decision: if any sync source fails partially (e.g., GitHub API returns an error mid-pagination), vulnscan does not crash and does not silently return a clean result. It returns whatever Findings it has, plus an `incomplete` warning, plus exit code 2. The caller knows the results may be incomplete.

---

## The exit code matrix

```
computeExitCode(findings, warnings, config):
  if hasIncomplete(warnings)          → 2   (data quality issue)
  else if findings meet failOn        → 1   (real vulnerabilities found)
  else                                → 0   (clean)
```

`failOn` defaults to `['critical', 'high']`. Configurable per project via `.vulnscanrc`.

---

## Configuration layers

Resolution order (later overrides earlier):

```
Defaults hardcoded in config.ts
  ↓
~/.vulnscanrc  (user home)
  ↓
<projectDir>/.vulnscanrc  (project)
  ↓
CLI flags (--fail-on, --offline)
  ↓
Environment variables (VULNSCAN_DB_PATH, GITHUB_TOKEN, VULNSCAN_NO_BOOTSTRAP)
```

---

## The local DB schema

Single table: `advisories`

```sql
CREATE TABLE advisories (
  id              TEXT,           -- OSV id (GHSA-xxx or MAL-xxx)
  package_name    TEXT,
  severity        TEXT,           -- critical | high | moderate | low
  title           TEXT,
  affected_ranges TEXT,           -- JSON array of semver ranges
  canonical_id    TEXT,           -- GHSA-xxx preferred; OSV id fallback
  last_seen_in_full_sync INTEGER, -- timestamp; used for OSV pruning
  PRIMARY KEY (id, package_name)
);
```

Separate table for sync metadata:

```sql
CREATE TABLE sync_metadata (
  source      TEXT PRIMARY KEY,   -- 'osv' | 'github'
  synced_at   INTEGER             -- Unix ms
);
```

**Schema migration:** All migrations run inline in `openDb()` via `safeAddColumn()` — no migration files, no migration runner. `safeAddColumn()` is idempotent and handles concurrent `ALTER TABLE` races in WAL mode.

---

## Module quick-reference

| File | One-line role |
|------|--------------|
| `cli.ts` | Entry point. Routes commands, owns AdvisoryStore lifecycle, computes exit code |
| `cli-args.ts` | Parses process.argv into ParsedArgs. No side effects |
| `scanner.ts` | Orchestrates: parse → sync → match → dedup. Returns ScanResult |
| `lockfile-parser.ts` | Reads package-lock.json into Dep[] |
| `lockfile-resolver.ts` | Classifies each lockfile entry (plain / workspace / alias / git) |
| `sync-orchestrator.ts` | Staleness check + per-source sync trigger. Clock-skew guard |
| `osv-sync.ts` | Downloads OSV ZIP, imports into AdvisoryStore |
| `github-advisory-sync.ts` | Paginates GitHub REST advisory API, upserts results |
| `advisory-store-sqlite.ts` | Production AdvisoryStore adapter backed by local-db.ts |
| `advisory-store-memory.ts` | Test AdvisoryStore adapter — in-memory, zero I/O |
| `local-db.ts` | Raw SQLite helpers, schema migrations, all SQL |
| `affected-range-matcher.ts` | Semver range evaluation: does version X fall in advisory range? |
| `deduplicator.ts` | Merges Findings from multiple sources by canonical_id |
| `output-renderer.ts` | Renders Findings as table (default) or JSON |
| `warnings.ts` | ScanWarning type + factory functions (incomplete / informational) |
| `severity-mapper.ts` | Maps OSV severity strings to the internal Severity type |
| `config.ts` | Loads + validates .vulnscanrc |
| `secrets.ts` | Scrubs API tokens from error messages before logging |
| `bootstrap.ts` | First-run DB seeding from GitHub Release asset |
| `skill-installer.ts` | Copies skill/SKILL.md to ~/.claude/skills/vulnscan/ |
| `ancestry.ts` | Resolves transitive dependency ancestry from lockfile |
| `types.ts` | Shared types: Advisory, AdvisoryStore, Finding, Severity, Dep, SemverRange |
