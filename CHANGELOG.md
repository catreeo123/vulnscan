# Changelog

## [0.2.22] — 2026-05-31

### Fixes

- **A malformed `package.json` no longer forces exit `2` (incomplete) on an otherwise-complete scan** — `parseLockfile` emitted an `incomplete` warning when `package.json` failed to parse. But the dependency set is built entirely from `package-lock.json`; `package.json` feeds only `buildAncestryMap` (the `via` ancestry-display field), which never affects whether a vulnerability is detected. Detection coverage is therefore complete, so the warning is now `informational` (exit `0`/`1` per findings) rather than `incomplete` (exit `2`, which signals possibly-missed packages). Aligns with the coverage-based warning rule used elsewhere (never-synced vs aged, empty version).
- **OSV full sync no longer overwrites a GitHub row's stable GHSA `canonical_id` on a shared-PK collision** — `upsertAdvisoryFromFullSync`'s `ON CONFLICT` guarded `type`, `severity`, `affected_ranges_json`, and `source` for `source='github'` rows but left `canonical_id = excluded.canonical_id` unguarded. An OSV mirror of a CVE that lacks a GHSA alias derives a CVE-id `canonical_id` and, on collision, flipped the GitHub row's stable GHSA identity to the CVE id — making it sync-order-dependent and breaking deduplication/suppression keyed on the GHSA id (the documented "stable cross-source identifier"). `canonical_id` now carries the same `CASE WHEN advisories.source = 'github'` guard as the other curated columns. (The GitHub `upsertAdvisory` path intentionally still lets GitHub's GHSA `canonical_id` win — GitHub is authoritative for its advisories.)

## [0.2.21] — 2026-05-31

### Fixes

- **`vulnscan update` now exits `2` (incomplete), not `1` (findings), when the OSV bulk download fails** — `runSync` (the forced-pull path behind `update`) awaited `syncOsv` with no `try/catch`, so a transient OSV network/HTTP failure (e.g. a 503) threw, propagated to the CLI's top-level catch, and set `process.exitCode = 1`. Exit `1` means "findings at/above threshold" — semantically wrong for a sync command that reports no findings, and an internal asymmetry: a GitHub failure in the same `runSync` already degrades to exit `2` via `syncGithubSafe`, while the OSV failure did not. `runSync` now wraps `syncOsv` in the same guard as `syncIfStale`, emitting an `incomplete` warning (→ exit `2`) and skipping the prune/cursor-advance on failure so a failed sync neither deletes live advisories against partial data nor masks itself as fresh. The GitHub sync still runs so a partial refresh proceeds.

## [0.2.20] — 2026-05-31

### Fixes

- **OSV full sync no longer relabels a GitHub malware advisory's `type` from `mal` to `cve` on a shared-PK collision** — `upsertAdvisoryFromFullSync`'s `ON CONFLICT` clause guarded `affected_ranges_json`, `severity`, and `source` for `source='github'` rows but left `type = excluded.type` unguarded. A GHSA-id malware advisory stored by the GitHub pass (`type='mal'`) can collide with an OSV mirror of the same GHSA id that derives `type='cve'` (no `MAL-`/`CVE-` alias), silently relabelling the stored row `cve`. Severity (the exit-code gate) was already preserved, so detection was unaffected — but the `type` field in `--format json` output and any consumer keying on `type === 'mal'` (the `/vulnscan` skill, policy engines) lost the malware classification. `type` now carries the same `CASE WHEN advisories.source = 'github'` guard as the other curated columns.

## [0.2.19] — 2026-05-31

### Fixes

- **A malware OSV entry that also carries a CVE alias is no longer mis-classified as `cve` (silent false negative)** — `osvEntryToAdvisories` derived `type` from `getBestId(entry)`, which prefers a `CVE-*` alias over the `MAL-*` id for the display id. So a `MAL-*` entry with a CVE alias yielded `type='cve'`, bypassing the `mal → critical` override in `resolveAdvisorySeverity`; the malicious package was stored at its (frequently under-rated or `LOW`) OSV severity and slipped under the default `failOn: [critical, high]` threshold — a malicious package reported clean. Malware classification is now derived independently of the display id (`entry.id` or any alias starting with `MAL-`), so the critical override can never be skipped. The fail-safe direction (a GHSA entry with a MAL alias is treated as malware) is preserved.
- **An npm-alias lockfile entry with a missing/empty version no longer reports false-clean** — `resolveEntry`'s alias branch fabricated `version: '0.0.0'` when `pkg.version` was absent (and kept `''` when empty), returning a scannable `Dep` behind only an `informational` warning. `matchAffected('0.0.0' | '', range)` is `false` for any real advisory range, so a vulnerable aliased package silently produced no Finding and exited `0`. A missing/empty alias version is now surfaced as an `incomplete` warning (exit `2`), mirroring the plain-dep empty-version guard.

## [0.2.18] — 2026-05-31

### Fixes

- **OSV `fixed`-only event with no preceding `introduced` no longer drops the whole Advisory (silent false negative)** — `eventsToRanges` guarded the `fixed` branch with `&& current`, so a range whose events start with a bare `{ "fixed": "X" }` (some feeds emit this to mean "all versions before X are vulnerable") produced no range at all → the `affected[]` block was skipped → the Advisory was never stored → every version reported clean. This mirrored the already-correct `last_affected`-first handling inconsistently. The `fixed` branch now synthesizes `introduced: '0'` when there is no open range, yielding `{ introduced: '0', fixed: 'X' }`.
- **OSV full Sync no longer overwrites a GitHub-Source Advisory's ranges/severity (silent false negative)** — the v0.2.16 fix preserved the `source` column on a shared-PK conflict but still let the OSV `upsertFromFullSync` overwrite `affected_ranges_json` and `severity`. Since the OSV mirror often lags GitHub (fewer/narrower ranges, lower severity) and GitHub Sync is incremental (won't re-fetch an unchanged Advisory), a later full Sync silently narrowed a GitHub Advisory's coverage — e.g. dropping a second disjoint range so a version in it stopped matching. The `ON CONFLICT` clause now preserves `affected_ranges_json` and `severity` for `source='github'` rows (GitHub's incremental Sync keeps them current).
- **A lockfile entry with an empty version string no longer reports false-clean** — `resolveEntry`'s plain-dep branch keyed on `pkg.version !== undefined`, so `"version": ""` became a `Dep` with `version: ''`; `matchAffected('', range)` is always `false`, so a vulnerable package silently produced no Finding and exited `0`. An empty/whitespace version is now surfaced as an `incomplete` warning (exit `2`), like a git-sourced dep, instead of being silently un-checkable.
- **Malware Advisory severity warning no longer misstates the severity** — for a `mal` Advisory with no upstream label, `mapSeverity` returned `high` plus an `informational` warning ("defaulting to 'high'"), and `resolveAdvisorySeverity` then overrode the severity to `critical` but passed the now-incorrect warning through. The warning is now suppressed for `mal` advisories (the malware rule, not the label default, sets the severity), so the emitted metadata matches the stored `critical` severity. Detection was already correct; only the warning text was wrong.
- **A malformed GitHub advisory with `null` vulnerabilities no longer stalls the GitHub Sync** — `ghAdvisoryToAdvisories` did `item.vulnerabilities.filter(...)` with no null guard, while the OSV path was already hardened (`a?.package?.ecosystem`). GitHub's schema permits `vulnerabilities: null` (and a null `package`); such an item threw, and because the pagination loop has no per-item guard the throw aborted the whole pass — the cursor never advanced, so every subsequent Sync re-hit the same page and never imported any later advisory (a permanent stall with accumulating false negatives). The access is now null-safe (`(item.vulnerabilities ?? []).filter((v) => v?.package?.ecosystem === 'npm')`), so the bad item is skipped and the Sync continues.

## [0.2.17] — 2026-05-31

### Fixes

- **A value-flag no longer greedily consumes a following flag token** — in `cli-args.ts`, a known value-flag (`--format`/`--fail-on`/`--dir`) given without its value would swallow the next argument even when that argument was itself a flag. `vulnscan scan . --format --fail-on critical` parsed to `format='--fail-on'` (silently wrong, falls through to table output) and silently dropped `--fail-on critical` with no warning; `--fail-on --offline` consumed `--offline` as the fail-on value, so the requested offline mode was silently ignored and the Scan went online. The parser now treats a `--`-prefixed next token as a missing value (warns and ignores, matching the end-of-args case) so the following flag is still honored.

## [0.2.16] — 2026-05-31

### Fixes

- **An empty-string `introduced` no longer silences an Advisory (silent false negative)** — `buildSemverRange` used `range.introduced ?? '0'`, but `??` only catches `null`/`undefined`. An empty-string `introduced` (allowed by the `SemverRange` type, and treated by OSV as equivalent to `"0"`) passed through and produced the comparator `">="`, which `semver.satisfies()` silently rejects as `false` for every version — so a vulnerable package was never flagged. Changed to `range.introduced || '0'` in the Affected Range Match.
- **`--offline`/`--no-sync` against a never-synced Local DB no longer reports false-clean (exit 0)** — `offlineStalenessWarnings` emitted an `informational` warning for a source whose cursor was `null` (never synced), the same class it uses for merely-aged data. A never-synced DB has zero coverage, so a Scan of it found no Findings and exited `0` ("clean") — a false-clean for a CI gate. A never-synced source now emits an `incomplete` warning (exit `2`); present-but-aged data remains `informational` (exit `0`).
- **OSV full Sync no longer strips the GitHub Source exemption on a shared-PK Advisory (silent false negative)** — a CVE-numbered Advisory shares its PK `(id, package_name)` across both feeds (`getBestId` prefers the CVE alias, which equals GitHub's `id`), so an OSV full Sync collided with a GitHub-Source row and its `ON CONFLICT DO UPDATE` overwrote `source` to `'osv'`. The still-live GitHub Advisory then became eligible for the OSV stale-prune and was deleted once OSV dropped it. `upsertAdvisoryFromFullSync` now preserves `source = 'github'` on conflict (`CASE WHEN advisories.source = 'github' THEN 'github' ELSE excluded.source END`), keeping the documented "GitHub advisories are never pruned" invariant intact.
- **OSV Local DB write failures now signal `incomplete`** — the per-row recovery loop in `syncOsv` caught `upsertFromFullSync` errors (decrementing `imported`, incrementing `skipped`) but pushed no warning, so a systematic write failure (e.g. disk full, WAL corruption) left the DB partially populated yet the Scan still exited `0`. `syncOsv` now returns an `incomplete` warning when one or more advisories fail to persist, yielding exit `2`.

### Internal

- `vitest.config.ts` excludes `**/.claude/**` so stale agent git-worktrees under `.claude/worktrees/` are not globbed and run as phantom duplicate test suites.

## [0.2.15] — 2026-05-31

### Fixes

- **A transient OSV Sync failure no longer crashes the Scan with a misleading exit 1** — `syncIfStale` called `syncOsv` with no `try/catch` (unlike the GitHub path's `syncGithubSafe`), so an OSV download/HTTP error (e.g. a 503) propagated out of `runScan` to the top-level handler and exited `1` — the code that means "Findings meet the Failure Threshold" — while aborting the Scan entirely instead of evaluating the lockfile against the existing Local DB. `scan`/`check` now catch an OSV Sync failure, emit an `incomplete` warning (scrubbed of secrets), and proceed against local data, yielding the correct exit `2` (incomplete). The OSV cursor is not advanced and `pruneStale` is not run on a failed Sync (a prune/cursor error is a local invariant and still propagates). The explicit `update` command remains strict — it errors if it cannot complete a full refresh.

## [0.2.14] — 2026-05-31

### Fixes

- **A single malformed OSV entry no longer aborts the entire Sync** — `osvEntryToAdvisories` read `affected[].package.ecosystem` directly, so an `affected[]` block missing (or with a null) `package` threw a `TypeError`. The conversion call in `syncOsv`'s parse loop is not wrapped in the per-entry `try/catch` that guards `JSON.parse` and the upsert, and `syncOsv` itself has no catch (unlike the GitHub path's `syncGithubSafe`), so the throw propagated out and crashed the whole Scan/`update` (exit 1) over one bad entry in the 100k+ OSV dump. The `affected[]` filter is now null-safe (`a?.package?.ecosystem`); a malformed block is skipped (counted in `skipped`) and the rest of the dump still imports — matching the existing per-row recovery contract.

## [0.2.13] — 2026-05-31

### Fixes

- **`check <pkg@>` with an empty or unparseable version no longer reports false-clean** — `vulnscan check lodash@` (trailing `@`, empty version) or `vulnscan check lodash@not-a-version` parsed to a non-empty name with an invalid version. `matchAffected`'s `semver.satisfies('', range)` returns `false` for every Advisory, so a vulnerable package silently produced no Findings and exited `0` ("✓ No findings") — a false safe signal. The `check` command now validates the version with `semver.valid()` and rejects an empty/unparseable version with the usage message and exit `1`, the same as a missing argument. The `lastAt <= 0` guard already covered unversioned scoped packages (`@scope/pkg`); this closes the trailing-`@`/garbage-version gap.

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
