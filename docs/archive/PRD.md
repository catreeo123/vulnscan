# vulnscan — Product Requirements Document

## Problem Statement

npm audit is the default tool for detecting vulnerable Node.js dependencies, but it has two significant limitations:

1. **Propagation lag.** npm audit queries the npm Advisory Database, which mirrors GitHub's Advisory Database. New CVEs often appear in OSV.dev and GitHub Advisory within hours of disclosure but take days to weeks to propagate into npm's mirror. Developers are left exposed during this window.

2. **No supply chain coverage.** npm audit only surfaces CVE-backed vulnerabilities. It does not detect malicious packages — backdoors, data exfiltration packages, protestware, and typosquatting packages with malicious payloads — which have no CVE and never appear in npm audit results.

Commercial tools like Aikido Security address both gaps but add subscription cost and external dependency. The goal is a self-hosted CLI that replaces the vulnerability and supply chain scanning functions of Aikido at zero ongoing cost.

---

## Solution

`vulnscan` is a TypeScript CLI distributed via `npx`. It:

- Syncs a local SQLite database from OSV.dev (CVE + MAL-* supply chain entries) and the GitHub Advisory Database directly
- Scans `package-lock.json` against the local database using semver range matching
- Deduplicates findings across sources, taking highest severity on conflict
- Outputs a human-readable colored table by default, or `--format json` for CI/CD and AI consumption
- Fails CI/CD pipelines on configurable severity thresholds (default: critical, high)
- Integrates as a Claude Code skill that explains findings and suggests upgrade paths

---

## User Stories

1. As a developer, I want to run `vulnscan scan .` in my project directory and see all vulnerable dependencies, so that I can fix them before committing.
2. As a developer, I want findings displayed as a colored table with severity, package name, version, and advisory ID, so that I can quickly prioritize what to fix.
3. As a developer, I want to run `vulnscan check lodash@4.17.20` to query a single package, so that I can verify a specific dependency before adding it.
4. As a developer, I want vulnscan to automatically sync its local database before scanning if the data is older than 24 hours, so that I never need to remember to update manually.
5. As a developer, I want to run `vulnscan update` to force a database sync at any time, so that I can get the latest data before an important review.
6. As a developer, I want git-sourced and npm-aliased dependencies to be skipped with a warning rather than silently passing, so that I am aware of dependencies that could not be checked.
7. As a developer, I want supply chain signals (`MAL-*`) to appear as findings alongside CVE vulnerabilities, so that I catch malicious packages in my dependency tree.
8. As a developer, I want to configure the failure threshold in a `.vulnscanrc` file, so that my project's risk tolerance is committed to source control.
9. As a CI/CD pipeline engineer, I want vulnscan to exit with a non-zero code when findings meet the failure threshold, so that builds fail automatically on critical or high severity vulnerabilities.
10. As a CI/CD pipeline engineer, I want to run `vulnscan scan --format json` and parse structured output, so that I can integrate findings into dashboards or other tooling.
11. As a CI/CD pipeline engineer, I want to configure vulnscan in a Bitbucket Pipeline step, so that every PR is scanned before merge.
12. As a CI/CD pipeline engineer, I want the failure threshold to be overridable via `--fail-on` flag, so that I can set different thresholds per pipeline step without changing the config file.
13. As a Claude Code user, I want to invoke a vulnscan skill that scans my project and explains each finding in plain English, so that I understand what the vulnerability means without looking it up.
14. As a Claude Code user, I want the skill to tell me the safe upgrade version and describe any breaking changes, so that I can fix findings without introducing regressions.
15. As a Claude Code user, I want supply chain signals explained with the nature of the malicious behavior (e.g. data exfiltration, backdoor), so that I can assess the actual risk.
16. As a security-conscious developer, I want the database synced from OSV and GitHub Advisory directly (not via npm's mirror), so that I catch vulnerabilities during the propagation window when npm audit would miss them.
17. As a developer on a team, I want vulnscan to require no API keys for its core functionality, so that it works in any environment without credential management.
18. As a developer, I want vulnscan installable via `npx vulnscan` with no global install required, so that onboarding is frictionless.
19. As a developer, I want the local database stored in a predictable location (e.g. `~/.vulnscan/db.sqlite`), so that it persists across projects and syncs only once per day regardless of how many projects I scan.
20. As a developer, I want findings to include a direct link to the advisory, so that I can read the full disclosure without additional searching.

---

## Implementation Decisions

### Module architecture

Seven modules with clear boundaries:

**LockfileParser**
Reads `package-lock.json` and returns a flat list of all transitive dependencies with name and resolved version. Handles npm lockfile v2/v3 format. Skips git-sourced and npm-aliased entries, emitting a named warning per skipped entry rather than silently passing them.

**OsvSync**
Downloads the OSV npm ecosystem dump (`npm/all.zip`) from Google Cloud Storage. Parses each JSON entry and upserts into Local DB. Handles both `CVE-*` vulnerability entries and `MAL-*` malicious package entries from the OpenSSF Malicious Packages feed.

**GithubAdvisorySync**
Paginates the GitHub GraphQL Security Advisory API to retrieve all npm-ecosystem advisories. Requires no authentication for public advisories (60 req/hr unauthenticated; `GITHUB_TOKEN` env var enables 5000 req/hr).

**SyncOrchestrator**
Reads the last-synced timestamp from Local DB. If older than the Staleness Threshold (default 24h, configurable), runs OsvSync then GithubAdvisorySync sequentially. Reports sync progress to stderr.

**LocalDb**
SQLite database at `~/.vulnscan/db.sqlite`. Two tables: `advisories` (id, source, type, package_name, affected_ranges_json, severity, title, url) and `sync_metadata` (source, last_synced_at). Provides typed read/write methods consumed by all other modules.

**AffectedRangeMatcher**
Given a `{name, version}` dep and the advisory list from Local DB, evaluates each advisory's semver ranges using the `semver` npm package. Returns matching advisories as Findings. This is the core algorithmic module — pure function, no I/O.

**Deduplicator**
Takes a list of Findings (potentially duplicated across OSV and GitHub Advisory for the same CVE). Merges by key `name@version + advisory-id`. On severity conflict between sources, takes the higher severity. Returns a deduplicated list.

### Data flow

```
vulnscan scan .
  └─ LockfileParser        parse package-lock.json → Dep[]
  └─ SyncOrchestrator      auto-sync if stale
  └─ LocalDb               query advisories for each package name
  └─ AffectedRangeMatcher  semver match version against ranges → Finding[]
  └─ Deduplicator          merge cross-source duplicates → Finding[]
  └─ OutputRenderer        table (default) or JSON (--format json)
  └─ exit code             0 = no findings above threshold, 1 = findings present
```

### CLI commands

- `vulnscan scan [path]` — scan project at path (default: `.`). Reads `package-lock.json`.
- `vulnscan check <pkg@version>` — query Local DB for a single package version.
- `vulnscan update` — force sync of all sources regardless of staleness.

### Output formats

- Default: colored table with columns: Severity | Package | Installed | Advisory ID | Title
- `--format json`: array of Finding objects with all fields
- Severity color coding: critical=red, high=orange, moderate=yellow, low=grey

### Failure threshold

Controlled by `--fail-on <levels>` flag (comma-separated) or `failOn` key in `.vulnscanrc`. Accepted values: `critical`, `high`, `moderate`, `low`. Default: `critical,high`. vulnscan exits 1 if any Finding's severity is in the threshold list.

### Config file

`.vulnscanrc` (JSON) searched at project root, then `~/.vulnscanrc`. Keys: `failOn` (string[]), `stalenessHours` (number).

### Semver edge cases

- Git deps (`github:`, `git+https://`): skipped, warning emitted
- npm aliases (`npm:other-pkg@1.0`): skipped, warning emitted
- Prerelease versions: matched using `semver.satisfies` with `includePrerelease: true`

### GitHub token

`GITHUB_TOKEN` env var is read if present and used as a Bearer token on GraphQL requests. Without it, sync proceeds at 60 req/hr which is sufficient for initial sync but may hit rate limits on large advisory sets. vulnscan warns if token is absent but does not fail.

### Claude Code Skill

Implemented as a slash command skill. Calls `vulnscan scan --format json`, parses the JSON output, then for each Finding:
- Explains the vulnerability or malicious behavior in plain English
- States the patched version (from Advisory data)
- Notes any known breaking changes in the upgrade path

---

## Testing Decisions

### What makes a good test

Tests verify observable behavior through public interfaces only. A test should survive complete internal refactoring — if renaming an internal function breaks a test, the test is testing implementation, not behavior. Tests are written one at a time (TDD vertical slice), not in bulk.

### Modules to test

**LockfileParser** — pure function, no I/O at test time (file content passed as string). Test behaviors:
- Returns correct dep list from a real `package-lock.json` fixture
- Includes transitive (not just direct) deps
- Skips git-sourced deps and emits a warning
- Handles lockfile v2 and v3 formats

**AffectedRangeMatcher** — pure function, no DB at test time (advisories passed as array). Test behaviors:
- Installed version within affected range → Finding returned
- Installed version outside affected range → no Finding
- `MAL-*` advisory → Finding with type `supply-chain-signal`
- Multiple overlapping ranges → single Finding
- Prerelease version correctly matched

**Deduplicator** — pure function. Test behaviors:
- Same CVE-ID from two sources → single Finding, higher severity wins
- Different CVE-IDs on same package → two Findings preserved
- Empty input → empty output

### Modules not unit-tested (integration/e2e only)

- `OsvSync`, `GithubAdvisorySync` — network I/O; covered by manual integration test
- `SyncOrchestrator` — thin orchestration; covered by e2e
- `LocalDb` — thin SQLite wrapper; covered by integration through Scanner
- `OutputRenderer` — visual; covered by e2e golden path
- `CLI` — one e2e test: scan a fixture project, assert non-zero exit on known vulnerable dep

### Test runner

`vitest` per TypeScript project conventions.

---

## Out of Scope

- `yarn.lock` and `pnpm-lock.yaml` support (v1: `package-lock.json` only)
- SAST / static code analysis
- License compliance scanning
- Container or image scanning
- Runtime monitoring
- Install-time blocking (that is Socket Firewall's domain)
- NVD direct integration (covered by OSV's ingestion of NVD)
- Socket.dev integration (OSV `MAL-*` entries cover the supply chain use case without API key or quota)
- Reachability analysis (which code paths actually call the vulnerable function) — Aikido/Snyk feature, out of scope

---

## Further Notes

- An ADR is pending for the per-source fetch strategy (OSV full dump vs GitHub GraphQL pagination vs Socket dropped). Should be written as `docs/adr/0001-per-source-fetch-strategy.md` before implementation begins.
- GitHub token is optional but recommended for teams. Without it, initial sync may be slow on large advisory sets.
- The OSV `MAL-*` malicious package feed is updated within ~3 days of a confirmed malicious package. This is sufficient for scanning installed deps but not for install-time blocking (which requires real-time detection).
- vulnscan replaces Aikido's dependency vulnerability and supply chain scanning functions. It does not replace Aikido's SAST, license compliance, or container scanning.
