# vulnscan Phase 2 — Product Requirements Document

## Problem Statement

The current vulnscan output is a flat table that is hard to act on: the same package may appear multiple times (once per CVE), URLs were truncated or pointed to the wrong page, and there is no indication of which direct dependency in `package.json` is responsible for pulling in a vulnerable transitive package. Developers cannot easily answer the question "which packages do I need to upgrade?".

Additionally, the first-time sync experience is slow: a new user must wait 3–5 minutes for the full OSV (195 MB) and GitHub Advisory (63 pages) sync to complete before seeing any results. This is a significant barrier to adoption.

Finally, subsequent syncs re-fetch the entire GitHub Advisory database (63 pages) even when only a handful of advisories have changed since the last sync, wasting time on every daily re-sync.

---

## Solution

Three improvements are delivered together:

1. **Grouped output** — replace the flat table with a severity-grouped, package-centred view that shows all CVEs per package in one block, indicates which root dependency pulls in the vulnerable package, and shows the patched version per CVE so the developer knows exactly what to upgrade to.

2. **Snapshot bootstrap** — host a weekly pre-built gzip-compressed SQLite database on GitHub Releases. New users download this snapshot (~15–18 MB) on first run instead of building the database from scratch, reducing cold-start time from 3–5 minutes to ~30 seconds.

3. **Incremental GitHub Advisory sync** — on subsequent syncs, pass `updated=>=<last_synced_at>` to the GitHub Advisory API to fetch only advisories modified since the last sync. This reduces sync cost from 63 pages to 1–3 pages in the steady state.

---

## User Stories

1. As a developer, I want findings grouped by severity with a header showing the count, so that I immediately see how many critical issues I have.
2. As a developer, I want each package shown once per severity group with all its CVEs listed beneath it, so that I can see the full exposure of one package at a glance.
3. As a developer, I want each CVE entry to include the title and a direct URL to the advisory, so that I can open the specific disclosure without extra searching.
4. As a developer, I want CVE IDs to link to `nvd.nist.gov/vuln/detail/<CVE-ID>` and GHSA IDs to link to `github.com/advisories/<GHSA-ID>`, so that the URL is always the authoritative source for that identifier type.
5. As a developer, I want transitive vulnerable packages to show `via <root-dep>` indicating the direct `package.json` dependency responsible, so that I know which package to upgrade or replace.
6. As a developer, I want the `via` annotation to trace back to the direct root dependency (not an intermediate in the chain), so that the actionable package is always shown.
7. As a developer, I want to see the patched version next to each CVE entry (e.g. `→ fix: ≥4.17.21`), so that I know the minimum safe version without reading the advisory.
8. As a developer, I want the patched version derived from the advisory's range data, so that it is always consistent with the advisory database.
9. As a developer, I want packages with no patched version available to omit the fix annotation silently, so that the output is not cluttered with "unknown" entries.
10. As a developer, I want `--format json` output to include `via` and `fix` fields so that CI/CD tooling can consume ancestry and fix data programmatically.
11. As a new user running vulnscan for the first time, I want the database to be ready in under 30 seconds, so that I do not wait 3–5 minutes before seeing my first scan results.
12. As a new user, I want the snapshot download to happen automatically when no local database exists, with a progress message, so that I do not need to read documentation or run a separate setup command.
13. As a new user, I want the first scan to use complete data (OSV + GitHub Advisory), so that the snapshot produces the same quality of results as a fully-synced database.
14. As a new user on a poor network where the snapshot download fails, I want vulnscan to fall back to a full sync automatically, so that the tool always works regardless of network conditions.
15. As a team lead distributing vulnscan, I want new team members to get a working database within 30 seconds of their first scan, so that onboarding friction is eliminated.
16. As a developer running daily scans, I want the GitHub Advisory sync to fetch only advisories updated since the last sync, so that subsequent scans complete in seconds rather than minutes.
17. As a developer, I want the incremental sync to automatically fall back to a full sync if no prior timestamp exists, so that the first sync after installing is still complete.
18. As a developer, I want the OSV sync to remain a full download (no incremental), since OSV does not provide a per-advisory update API, so that OSV data is always complete.
19. As an operator maintaining the snapshot, I want the pre-built database rebuilt and uploaded to GitHub Releases automatically every week via GitHub Actions, so that new users always get reasonably fresh data.
20. As a developer, I want the snapshot to be gzip-compressed to reduce download size from ~51 MB to ~15 MB, so that the cold-start download is fast even on slow connections.

---

## Implementation Decisions

### Grouped output renderer

The output renderer is rewritten to produce severity-grouped output. For each severity level in descending order (critical → high → moderate → low), a coloured header shows the level name and finding count. Beneath it, findings are grouped by package name and version. Each package block shows:

- Package name, installed version, and optionally `[via <root-dep>]` on the first line
- One indented line per CVE/GHSA: advisory ID, truncated title (60 chars), optional `→ fix: ≥<version>`, and canonical URL

The `renderTable` function is replaced by `renderGrouped`. The `renderJson` function is unchanged. The `canonicalUrl` helper (CVE → NVD, GHSA → GitHub Advisory) introduced in phase 1 is reused.

The patched version is extracted from the advisory's `ranges` field: the first `fixed` value across all structured ranges is shown. Advisories using `rawRange` only (GitHub-sourced) do not show a fix annotation, as parsing semver range strings is deferred to future work.

### Lockfile ancestry tracker

A new deep module computes, for each package in the lockfile, the direct root dependency from `package.json` that transitively pulls it in. The module:

1. Reads the root entry's `dependencies`, `devDependencies`, and `optionalDependencies` to identify direct root deps.
2. Builds a forward dependency map from each package's `dependencies` field in the lockfile.
3. Runs a BFS from each root dep, marking all reachable transitive packages with the root dep name as their ancestor.
4. Returns a `Map<packageName, rootDepName>`. Packages that are themselves root deps are absent from the map (no `via` annotation needed).

The `Dep` type gains an optional `via?: string` field. The lockfile parser populates it using the ancestry map. The `Finding` type gains an optional `via?: string` field. The range matcher copies `via` from the `Dep` it processes. This ancestry data flows through the pipeline without modification.

This module only operates on v2/v3 lockfile format (which has `packages` with `dependencies` fields). v1 lockfiles produce no ancestry data; `via` is undefined.

The `Dep` and `Finding` type shapes, from prototype:
```
Dep    = { name: string; version: string; via?: string }
Finding = { name: string; version: string; via?: string; advisory: Advisory }
```

### Snapshot downloader

A new module handles first-run database bootstrap. It is invoked by the CLI before `openDb()` when the database file does not exist at the configured path. The module:

1. Emits a progress message to stderr.
2. Downloads a gzip-compressed SQLite file from the configured snapshot URL (default: GitHub Releases latest download URL for this repo).
3. Decompresses the stream to the database path using Node's built-in `zlib`.
4. On any download or decompression error, catches and rethrows a sentinel error that the caller interprets as "fall back to full sync."

The snapshot URL is a constant in the module, defaulting to the public GitHub Releases URL. It can be overridden via the `VULNSCAN_SNAPSHOT_URL` environment variable for testing.

### GitHub Actions snapshot workflow

A scheduled workflow runs weekly (Sunday midnight UTC). It:

1. Checks out the repo and installs dependencies.
2. Runs `vulnscan update` to build a fresh database.
3. Gzip-compresses the resulting `.sqlite` file.
4. Uploads the compressed file as a GitHub Release asset under the `latest` release tag using `gh release upload`.

This workflow requires `GITHUB_TOKEN` (automatically available in Actions) and write permission to releases.

### Incremental GitHub Advisory sync

The GitHub Advisory sync function gains an optional `since?: number` (Unix timestamp ms) parameter. When provided, the initial API URL includes `updated=>=<ISO8601>`. When absent, the full unfiltered URL is used.

The sync orchestrator passes `getLastSyncedAt(db, 'github')` as the `since` parameter when it exists. On first sync (null), no `since` is passed and the full sync runs.

---

## Testing Decisions

Good tests verify observable behavior through public interfaces, not implementation details. They survive internal refactors. Prior art: `lockfile-parser.test.ts` (fixture-based unit tests), `cli.e2e.test.ts` (process spawn with fixture projects).

**Lockfile ancestry tracker** — tested in isolation with lockfile JSON fixtures representing:
- Direct root dep (no `via` expected)
- One-level transitive dep (e.g. root → `dd-trace` → `protobufjs`)
- Multi-level transitive dep (root → A → B → C, expect C's `via` = A)
- Package depended on by multiple root deps (first BFS to claim it wins)
- v1 lockfile format (no `dependencies` field, `via` should be undefined for all)

**Grouped output renderer** — tested with a fixed set of `Finding` objects (no DB, no lockfile):
- Correct severity grouping order
- `via` annotation appears when present, absent when not
- Fix annotation appears for structured ranges with `fixed`, absent for `rawRange`-only advisories
- Canonical URL format (CVE → NVD, GHSA → GitHub)
- Empty findings renders clean "no findings" message

**Snapshot downloader** — tested with a mock HTTP server serving a known gzip-compressed SQLite fixture:
- Happy path: file exists at expected path after download
- Network error: throws sentinel, caller falls back to full sync

**Incremental sync** — not unit tested directly; the `since` parameter is a one-line change to the URL construction. The existing e2e test suite covers end-to-end correctness.

---

## Out of Scope

- Parsing `rawRange` semver strings to extract fix versions from GitHub-sourced advisories (deferred; requires semver range AST parsing).
- Showing the full transitive chain (root → A → B → C) rather than just the root dep.
- Packages depended on by multiple root deps showing all roots (only first BFS to claim it is shown).
- OSV incremental sync (OSV does not provide a public per-advisory update endpoint).
- Snapshot integrity verification (checksum / signature) — deferred to a future security hardening pass.
- Windows path handling differences for the snapshot download path.

---

## Further Notes

The `via` field requires v2/v3 `package-lock.json` (npm ≥7). Projects using v1 lockfiles will not see the `via` annotation. This is acceptable since npm ≥7 is standard for any project using Node 18+.

The weekly snapshot rebuild means new users see data up to 7 days old. The existing 24-hour staleness check ensures that after the first scan, the database syncs to current within one day. The snapshot is only a cold-start accelerator, not a substitute for ongoing sync.
