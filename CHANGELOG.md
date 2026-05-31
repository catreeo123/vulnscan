# Changelog

## [0.2.12] — 2026-05-31

### Fixes

- **Multi-range Advisory no longer overwritten on upsert (silent false negative, #48)** — A single GitHub Advisory that lists one package across multiple disjoint version ranges (e.g. axios GHSA-3g43-6gmg-66jw: `>= 1.0.0, < 1.15.2` and `>= 0.19.0, < 0.31.1`) emitted one Advisory per `vulnerabilities[]` entry. All shared PK `(id, packageName)`, so the last-write-wins upsert dropped every range but the last — a version in a dropped range produced no Finding. `ghAdvisoryToAdvisories` now groups npm vulns by package and unions their ranges into one Advisory; `osvEntryToAdvisories` does the same across multiple `affected[]` blocks for one package. The `imported` count now reflects unique advisories written.
- **GitHub-Source advisories no longer pruned by the OSV full Sync (silent false negative, #49)** — `pruneStaleAdvisories` deleted by `last_seen_in_full_sync` with no Source filter. Because GitHub Sync is incremental (`updated>=since`), a static advisory is upserted once and its timestamp then freezes, so after the 7-day grace the OSV prune deleted live GitHub-only and malware advisories. Added a `source` column (migration backfills from url); the prune now deletes only `source = 'osv'` rows, exempting GitHub-Source advisories by construction.

## [0.2.11] — 2026-05-30

### Fixes

- **GitHub Advisory progress line now reports per-pass counts** — `imported` was a single counter shared across both sync passes (reviewed, then malware) and never reset, so the malware pass printed the cumulative total tagged with the malware label (e.g. "malware — 38 imported" when malware actually added 30). Each pass now reports its own delta plus the running cumulative (`30 imported (38 total)`). Final returned totals are unchanged — labeling fix only.

## [0.2.10] — 2026-05-29

### Fixes

Eight correctness/hardening fixes from a whole-repo review (PRD #32, issues #33–#40):

- **GitHub malware advisories are now forced to `critical`** — the `mal → critical` override existed only in OSV sync; GitHub's malware feed stored its reported severity verbatim, so a malicious package GitHub under-rated (`moderate`/`low`) could slip past `--fail-on critical`. Extracted `resolveAdvisorySeverity()` so both sync paths share one rule. Closes #33.
- **`vulnscan update` now exits 2 on an incomplete sync** — `runSync` returned `void` and `update` always exited 0, so a failed GitHub Advisory sync let CI overwrite the good `db-latest` asset with degraded data. `runSync` now returns the collected warnings and `update` fails safe (CI keeps the last-good DB). Closes #34.
- **First-run bootstrap is now atomic** — the download streamed straight into `db.sqlite`; an interrupted download left a corrupt file that bricked every subsequent run. Now downloads to a temp path and atomically renames on success, cleaning up on failure. Closes #35.
- **`--fail-on=value` (equals form) is now honored** — only the space-separated form parsed; `--fail-on=critical` was silently dropped, reverting the fail gate to defaults. A pre-commit review of this change caught two follow-on edges, now also fixed: a value passed to a boolean flag (`--offline=false`) was discarded and *enabled* the flag (inverting intent), and an empty equals value (`--fail-on=`) was stored as `""`; both now warn and fall back instead. Closes #36.
- **`vulnscan check @scope/pkg` without a version now errors** — it previously parsed to an empty package name and silently reported clean. Closes #37.
- **A malformed `.vulnscanrc` now warns** instead of being silently ignored. Closes #38.
- **Importing `cli.ts` no longer dispatches a command** — the module-scope entry call is guarded by a realpath entry-point check, so importing it performs no DB/network/exit-code side effects. Closes #39.
- **Release workflow hardened against tag-name shell injection** — `github.ref_name` is passed via an env var and quoted. Closes #40.

## [0.2.9] — 2026-05-27

### Fixes

- **Bootstrap DB download now targets the `db-latest` release tag** — `RELEASES_API` in `bootstrap.ts` changed from `releases/latest` to `releases/tags/db-latest`. The daily CI workflow publishes the advisory DB under the `db-latest` tag; `releases/latest` pointed at the most recent semver release which does not include the DB asset. Closes #29.

## [0.2.8] — 2026-05-27

### Chores

- Added `repository` field to `package.json` so GitHub links the published package to the repository.

## [0.2.7] — 2026-05-27

### Fixes

- **`npm pack` now always ships fresh compiled JS** — added `"prepare": "npm run build"` so pack/publish always rebuilds `dist/` first. Without this, `0.2.6` was initially packed with stale compiled output that didn't include the 422 fix.

## [0.2.6] — 2026-05-27

### Fixes

- **GitHub Advisory incremental sync no longer 422s** — `toISOString()` emits milliseconds (e.g. `2025-01-01T00:00:00.000Z`) but the GitHub `/advisories?updated=` filter rejects them with `422 Unprocessable Entity`. The `.000Z` suffix is now stripped to produce the `...T00:00:00Z` form the API expects. Without this fix, any incremental sync (i.e. after the first full sync stored a cursor) silently fell back to OSV-only data.

## [0.2.5] — 2026-05-27

### Fixes

- **Supply Chain Signals now detected** — `osv-sync.ts` previously discarded every OSV MAL-* advisory (OpenSSF Malicious Packages) because those entries use `affected.versions` (exact version list) instead of `affected.ranges` (semver ranges). The `semverRanges.length === 0` guard caused a silent `continue` before any advisory was stored, so vulnscan downloaded malware data but never detected anything. Fix 1: after computing semver ranges from `affected.ranges`, if the result is empty and `affected.versions` is present, synthesize a point-range `{ introduced: v, lastAffected: v }` per valid semver version. Invalid non-semver version strings are skipped. Fix 2: MAL-* advisories always get `critical` severity regardless of the OSV severity label (which is often absent for malware entries). Closes #26.

## [0.2.4] — 2026-05-27

### Fixes

- **Defence-in-depth: loop-push for unbounded warning arrays** — replaced four `warnings.push(...big)` spread sites in `sync-orchestrator.ts` and `scanner.ts` with `for…of` loops. V8's function-argument limit (~125k) meant that any source returning 200k+ warnings would crash with `RangeError: Maximum call stack size exceeded`. The root cause (OSV producing 100k severity warnings) is fixed in #23 / v0.2.3; this change ensures no future unbounded warning source can re-introduce the same crash class. Closes #24.

## [0.2.3] — 2026-05-27

### Fixes

- **OSV severity warning dedupe** — `syncOsv` previously accumulated one `informational` warning per advisory that lacked severity metadata. On a full 211k-advisory OSV sync, this produced ~100k warnings which `sync-orchestrator` then spread into a result array, triggering V8's `Maximum call stack size exceeded` crash on fresh installs. Warnings are now collapsed into a single summary (e.g. `"42 advisories have unknown or missing severity metadata; defaulted to 'high' (fail-safe escalation)"`). Zero warnings are returned when all entries carry valid severity. Closes #23.

## [0.2.2] — 2026-05-27

### Tests

- **`computeExitCode` — incomplete priority** — new unit tests lock the exit-code priority invariant: incomplete warning beats qualifying findings (exit 2 > exit 1). Covers gap where a future refactor could silently invert the guard order.
- **`computeExitCode` — edge cases** — empty `failOn` array exits 0; `moderate` at-threshold and below-threshold boundaries; informational-only warning does not override exit 1.
- **`renderHelp` content contract** — five unit tests via `run(['--help', topic])` pin that each help topic contains required option names and exit-code notes. Previously `renderHelp` had zero content tests.
- **`--format json` exit code** — e2e tests now assert `result.status` (not just JSON parseability) for both `scan` and `check`. Catches the silent-exit-0 failure mode where findings are returned but the process exits clean.
- **`check --format json` schema** — asserts `schemaVersion` is the first key and that finding shape matches the skill consumer contract.

## [0.2.1] — 2026-05-27

### Fixes

- **`--fail-on` threshold semantics** — re-ships the floor fix from #20 which was missing from the 0.2.0 tarball published by a parallel agent.

## [0.2.0] — 2026-05-27

### New features

- **`--version` / `-V` flag** — print the installed semver version and exit 0. Closes #19.
- **`vulnscan skill --help`** — `skill` subcommand now has its own help page instead of falling through to global help. Closes #21.

### Fixes

- **`--fail-on` threshold semantics** — `--fail-on low` now fails on `low`, `moderate`, `high`, and `critical` (floor semantics, matching `npm audit --audit-level`). Previously it was exact-match only. The default config `["critical", "high"]` is unaffected. Closes #20.

## [0.1.1] — 2026-05-27

### Refactors

- **Sync injection seam** — `ScanInput` and `CheckInput` accept `sync?: SyncFn`. Tests inject stubs directly; no `vi.mock(sync-orchestrator)` needed. Production default unchanged (`syncIfStale`).
- **`run(argv): Promise<number>`** — `cli.ts` exports `run()` returning an exit code instead of calling `process.exit()` inline. Preserves stdout-flush invariant (M1). Module-level wrapper sets `process.exitCode`.
- **`stalenessMs` on `Config`** — `loadConfig` now computes `stalenessMs` from `stalenessHours` once at the config boundary. Callers use `config.stalenessMs` directly; the `* 60 * 60 * 1000` conversion no longer appears at call sites.

## [0.1.0] — 2026-05-27

### Breaking changes

- **JSON output now includes `schemaVersion: "1"` as the first key.** Consumers parsing `--format json` must tolerate this new field. Future breaking changes will increment this value; additive changes will not.
- **Exit code 2 now takes priority over exit code 1.** When a scan has both qualifying findings and incomplete warnings (e.g. git-sourced deps skipped), the process exits 2, not 1. CI pipelines gating on exit code 1 should also handle exit code 2.

### New features

- **`--offline` / `--no-sync` flag** — skip the staleness check and advisory sync entirely. Useful in air-gapped or CI environments where the DB is pre-populated. Emits `informational` warnings if the DB is stale or missing.
- **Exit code matrix** — `scan` and `check` now exit `0` (clean), `1` (findings at or above `--fail-on` threshold), or `2` (incomplete scan — git deps skipped, sync failed, or page limit hit). Exit 2 takes priority over exit 1.
- **Typed `ScanWarning` shape** — warnings in JSON output are now structured objects `{ class: 'incomplete' | 'informational', message: string }` internally. Wire format (`warnings: string[]`) is preserved for backwards compatibility.
- **Severity mapper with fail-safe escalation** — advisories with unknown or missing severity are escalated to `high` with an `informational` warning instead of being silently dropped.
- **Workspace + alias resolution** — npm workspaces (`link: true`, glob match) are detected and excluded from advisory lookup. npm aliases are resolved to the target package name with an `informational` warning.
- **GitHub Advisory malware pass** — a second pagination pass with `type=malware` fetches malicious package advisories not included in the default `type=reviewed` results. Malware advisories are stored with `type: 'mal'`.
- **SQLite `busy_timeout = 5000`** — reduces "database is locked" errors under concurrent scan + sync.
- **Double-checked staleness** — `syncIfStale` re-reads cursors after the initial staleness decision to short-circuit if a parallel process already synced.
- **Clock-skew detection** — if a sync cursor is set in the future (system clock jumped), a forced re-sync is triggered with an `informational` warning.
- **`schemaVersion` + `MAX_PAGES` warning + clock-skew guard** — JSON output is versioned; hitting the GitHub Advisory page cap emits an `incomplete` warning; clock skew is detected and reported.
- **Deterministic advisory ordering** — `getAdvisoriesForPackage` now sorts by `canonical_id ASC, id ASC`, ensuring consistent output across runs.

### Bug fixes

- **OSV cursor advanced after `pruneStale`** (not before) — prevents stale advisories surviving if sync is interrupted mid-prune.
- **GitHub Advisory cursor not advanced on page-limit truncation** — a truncated sync no longer stamps the cursor as fully current; the next run will retry from the last known position.
- **`syncGithubSafe` emits `incomplete` warning on error** — auth failures (expired token, 403, network error) now propagate as `incomplete` warnings and produce exit 2 instead of silently falling back to OSV-only coverage.
- **Clock-skew warning survives double-check short-circuit** — the informational warning is now emitted even when a parallel process synced between the first and second staleness reads.
- **OSV `canonicalId` prefers GHSA alias over CVE fallback** — reduces advisory double-counting when the same CVE appears in both OSV and GitHub Advisory sources.
- **GHSA regex requires exactly 4-char segments** — `{4}` quantifier prevents short tokens like `GHSA-a-b-c` from producing incorrect `canonicalId` values.
- **`depCount` excludes local workspace deps** — the reported "checked N packages" count no longer includes workspace packages that were skipped.
- **`github:`, `bitbucket:`, `gitlab:` lockfile shorthands detected as git deps** — these npm shorthand formats now emit `incomplete` warnings instead of being silently omitted.
- **`runSync` surfaces page-limit warnings to stderr** — the `update` command now reports truncated sync to the user.

### Internal

- `AdvisoryStore` seam introduced — `SqliteAdvisoryStore` wraps `local-db.ts`; `InMemoryAdvisoryStore` used in tests. All sync and scan paths go through the interface.
- `lockfile-resolver.ts` extracted from `lockfile-parser.ts` — `resolveEntry()` handles plain deps, workspaces, aliases, and git sources.
- `severity-mapper.ts` extracted — shared between OSV and GitHub Advisory sync paths.
- `warnings.ts` extracted — `incomplete()` and `informational()` helpers; `hasIncomplete()` predicate used by exit-code logic.

## [0.0.1] — initial release

- OSV bulk download sync
- GitHub Advisory API pagination
- `package-lock.json` v2/v3 parsing
- Semver range matching
- `scan`, `check`, `update` commands
- `--format json` output
- `.vulnscanrc` config file
- Bootstrap from GitHub release on first run
