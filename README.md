# vulnscan

Scan npm dependencies for vulnerabilities using a local advisory database synced from [OSV](https://osv.dev) and [GitHub Advisory Database](https://github.com/advisories).

Unlike `npm audit`, vulnscan works offline after the first sync and supports fine-grained severity filtering per project.

## Installation

```bash
npm install -g @catreeo123/vulnscan
```

Or from source:

```bash
npm install && npm run build && npm link
```

## Usage

```bash
# Scan current directory (reads package-lock.json)
vulnscan

# Scan a specific directory
vulnscan scan /path/to/project

# Check a single package
vulnscan check lodash@4.17.20

# Force a fresh advisory sync
vulnscan update

# Register the /vulnscan Claude Code skill
vulnscan skill install

# Show help
vulnscan --help
```

### Options

| Flag | Description |
|------|-------------|
| `--format json\|table` | Output format (default: `table`) |
| `--fail-on <csv>` | Severities that exit non-zero, e.g. `critical,high` (overrides `.vulnscanrc`) |
| `--offline`, `--no-sync` | Skip advisory sync — use existing local data |
| `--dir <path>` | Directory for `.vulnscanrc` lookup (`check` only) |
| `--help`, `-h` | Show usage |

### Exit codes

- `0` — clean: no findings at or above `--fail-on` threshold, no incomplete warnings
- `1` — findings: one or more findings meet the `--fail-on` severity threshold
- `2` — incomplete: advisory data may be missing (e.g. sync failed, git-sourced deps skipped); takes priority over exit 1

### JSON output

`--format json` emits:

```json
{
  "schemaVersion": "1",
  "findings": [
    {
      "name": "lodash",
      "version": "4.17.20",
      "via": "webpack",
      "advisory": {
        "id": "CVE-2021-23337",
        "canonicalId": "GHSA-35jh-r3h4-6jhm",
        "type": "cve",
        "severity": "high",
        "title": "Command Injection in lodash",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
      },
      "fix": "4.17.21"
    }
  ],
  "warnings": []
}
```

`fix` is `undefined` when no fix is known. `advisory.type` is `"cve"` for vulnerabilities or `"mal"` for malicious package reports. Full schema: [`docs/output-schema.md`](docs/output-schema.md).

## Configuration

Create `.vulnscanrc` at your project root or `~` (home wins if both exist):

```json
{
  "failOn": ["critical", "high"],
  "stalenessHours": 24
}
```

`--fail-on` on the CLI overrides `failOn` from the config file.

## Environment variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token — without it, advisory sync is rate-limited to 60 req/hr |
| `VULNSCAN_DB_PATH` | Override the SQLite database path (default: `~/.vulnscan/db.sqlite`) |

## How it works

On first run, vulnscan downloads the full OSV npm advisory feed and paginates the GitHub Advisory REST API into a local SQLite database. Subsequent scans reuse this cache and only re-sync when it's older than `stalenessHours` (default: 24h).

Each scan reads your `package-lock.json`, resolves the full dependency tree (including transitive deps), and checks every package against the local advisory database using semver range matching. Findings are deduplicated across sources using GHSA IDs.

## Development

```bash
npm test               # run all tests
npm run test:watch     # watch mode
npm run build          # compile TypeScript → dist/

# Run a single test file
npx vitest run src/scanner.test.ts

# Run a single test by name
npx vitest run src/scanner.test.ts -t "scan returns findings"
```

No lint script is configured — TypeScript strict mode (`strict: true`) catches type errors at build time.
