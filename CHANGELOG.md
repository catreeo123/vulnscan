# Changelog

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
