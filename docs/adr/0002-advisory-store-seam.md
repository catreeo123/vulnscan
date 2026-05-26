# ADR-0002 — AdvisoryStore repository seam

**Status:** Accepted — proceed with current scope; do not widen to batch API

**Date:** 2026-05-27

## Context

`local-db.ts` exported nine functions (schema/migration, advisory persistence, sync metadata). All consumers passed a raw `Database.Database` instance. Tests for `scanner.ts` required a real SQLite file in a temp directory, with `beforeEach`/`afterEach` boilerplate for setup and cleanup.

Architecture review (post-tier4-synthesis A2) proposed an `AdvisoryStore` interface plus in-memory adapter as a pilot to determine whether the seam reduces test complexity.

## Decision

Introduce `AdvisoryStore` (defined in `types.ts`) and two adapters:

- `InMemoryAdvisoryStore` (`advisory-store-memory.ts`) — for tests; zero I/O
- `SqliteAdvisoryStore` + `openStore()` (`advisory-store-sqlite.ts`) — wraps `local-db.ts` for production

All layers (`osv-sync`, `github-advisory-sync`, `sync-orchestrator`, `scanner`, `cli`) now accept `AdvisoryStore` instead of `Database.Database`.

## Pilot results

**Metric:** lines removed from `beforeEach`/`afterEach` blocks and discarded imports in converted test files.

### `scanner.test.ts`

| | Before | After |
|---|---|---|
| Removed imports | `node:fs`, `node:os`, `node:path`, `local-db.js`, `better-sqlite3` | — |
| `beforeEach` body | 2 lines (mkdtemp + openDb) | 1 line (`new InMemoryAdvisoryStore()`) |
| `afterEach` block | 4 lines (db.close + rmSync) | **deleted** |
| Net | — | **−10 lines of boilerplate** |

### `sync-orchestrator.test.ts`

Removed `vi.mock('./local-db.js', ...)` + dynamic `local-db.js` re-import. Replaced with inline `makeStore()` helper. Test logic unchanged; no SQLite dependency.

### `github-advisory-sync.test.ts`

Removed `vi.mock('./local-db.js', ...)` + `setLastSyncedAt` import. Replaced `makeDb()` (partial `Database.Database` mock) with `makeStore()` (partial `AdvisoryStore` mock). Assertions on `store.setLastSyncedAt` are simpler: two-argument call `(source, ts)` vs the previous three-argument `(db, source, ts)` pattern.

## Stumbling block: batch transaction in `osv-sync.ts`

The original `osv-sync.ts` used `db.transaction()` to commit all advisories atomically. `AdvisoryStore` has no `transaction()` method.

**Resolution for this ADR:** Dropped the transaction wrapper. Each `store.upsertFromFullSync()` call is now an individual write. This is safe because the per-row `try/catch` inside the loop already prevented mid-batch atomicity in the original code (SQLite rolled back on uncaught exception, but exceptions were caught). The practical difference is performance (N individual writes vs one batch commit) not correctness.

**If batch performance becomes a bottleneck:** Add `batch(advisories: Advisory[], fullSyncStartedAt: number): void` to `AdvisoryStore`. `SqliteAdvisoryStore` implements it with `db.transaction()`; `InMemoryAdvisoryStore` implements it as a plain loop.

## Consequences

- `local-db.ts` remains the single source of truth for SQLite schema, migrations, and row mapping. `SqliteAdvisoryStore` delegates entirely to it — no duplication.
- `openDb()` from `local-db.ts` is no longer called by application code. Use `openStore()` from `advisory-store-sqlite.ts` instead.
- New tests that would previously need a real SQLite file can use `InMemoryAdvisoryStore` with zero setup.
- `mapRowsSafely` (corrupt row skip-and-warn) stays inside `local-db.ts` / `SqliteAdvisoryStore`. The `AdvisoryStore` interface does not expose it — in-memory data is never corrupt.
- Broader migration recommendation: the seam is proven. File follow-up issues if any remaining tests still use `openDb` directly.
