# vulnscan — Bounded Context

## Purpose

CLI tool that scans Node.js project dependencies for security vulnerabilities and supply chain risks. Queries multiple upstream vulnerability databases directly, bypassing npm Advisory's propagation lag.

---

## Glossary

### Finding
A security issue surfaced by vulnscan for a specific package version. Covers both CVE-backed vulnerabilities and supply chain signals. The canonical unit of output. A Finding has a severity, a source, and a package identity.

### Vulnerability
A Finding backed by a CVE identifier (`CVE-*`). Sourced from OSV.dev or GitHub Advisory Database. Has a CVSS severity rating (critical / high / moderate / low).

### Supply Chain Signal
A Finding backed by a malicious package report (`MAL-*`). Sourced from OSV.dev via the OpenSSF Malicious Packages repository. Indicates intentionally malicious behavior — backdoors, data exfiltration, protestware, typosquatting with malicious payload.

### Advisory
The raw record from an upstream Source that a Finding is derived from. A single Vulnerability may be backed by multiple Advisories from different Sources.

### Source
An upstream vulnerability database queried by vulnscan. Two active sources:
- **OSV** — Google Open Source Vulnerabilities database. Covers `CVE-*` vulnerabilities and `MAL-*` supply chain signals via the OpenSSF Malicious Packages feed.
- **GitHub Advisory** — GitHub's security advisory database, queried directly (not via npm). Additional CVE coverage for the npm ecosystem.

### Local DB
A local data store populated by syncing from all Sources. Scans run against the Local DB, not live upstream APIs. Freshness is controlled by the Sync operation.

### Sync
The operation that pulls latest Advisory records from all Sources into the Local DB. Triggered automatically before a Scan when the Local DB is older than the Staleness Threshold. Also triggered explicitly via `vulnscan update`.

### Staleness Threshold
Maximum age of the Local DB before an automatic Sync is triggered. Configurable. Default: 24 hours.

### Sync Strategy
How each Source populates the Local DB during a Sync:
- **OSV** — full npm ecosystem dump downloaded as a single archive, then imported. Includes both `CVE-*` and `MAL-*` entries.
- **GitHub Advisory** — paginated GraphQL API pull of all npm advisories.

### Deduplication
The process of merging Advisories from multiple Sources that describe the same Vulnerability. Keyed on `package@version + CVE-ID`. When Sources disagree on severity, the highest severity wins.

### Scan
The primary operation. Reads `package-lock.json`, extracts the full transitive dependency tree, matches each package version against the Local DB via Affected Range Match, and returns a list of Findings.

### Check
A secondary operation. Queries the Local DB for a single package version specified by the user (e.g. `lodash@4.17.20`). Returns all Findings for that package.

### Transitive Dependency
A package not directly declared in `package.json` but pulled in by a direct dependency. Scans cover the full transitive tree, not just direct dependencies.

### Affected Range Match
The comparison that determines whether an installed package version falls within an Advisory's vulnerable version range. Uses semver range evaluation. Git-sourced deps and npm-aliased deps are skipped with a warning — not treated as clean.

### Lockfile
The file vulnscan reads to extract the full dependency tree. Supported: `package-lock.json`. Out of scope (v1): `yarn.lock`, `pnpm-lock.yaml`.

### Failure Threshold
The severity level at which vulnscan exits non-zero, failing a CI/CD pipeline step. Configurable via `--fail-on` flag or config file. Default: `critical,high`.

### Config File
A `.vulnscanrc` file at project root or user home. Stores Failure Threshold and source preferences. Values are overridden by environment variables and CLI flags.

### Severity
A rating assigned to a Vulnerability. Four levels in descending order: `critical`, `high`, `moderate`, `low`. Derived from CVSS score via the upstream Source. When Sources conflict, highest severity wins.

### Bootstrap
The one-time operation that seeds the Local DB on a fresh install by downloading a pre-built compressed advisory snapshot from the latest GitHub release asset (`db.sqlite.gz`). Runs silently before the first Scan or Check when no Local DB exists. Falls back to a full Sync if the download fails. Skipped when `VULNSCAN_NO_BOOTSTRAP` is set.

### Claude Code Skill
A vulnscan integration for Claude Code that runs a Scan, parses the JSON output, and provides active advisory: explains each Finding, gives the safe upgrade version, and describes the breaking change risk. Invoked as a slash command inside Claude Code sessions. Implementation contract: `.claude/skill-contract.md`.

---

## Boundaries

vulnscan covers:
- Dependency Vulnerabilities (`CVE-*`, via OSV + GitHub Advisory)
- Supply Chain Signals (`MAL-*`, via OSV)

vulnscan does not cover:
- SAST / static code analysis
- License compliance
- Container or image scanning
- Runtime monitoring
- Install-time blocking (use Socket Firewall for that)
