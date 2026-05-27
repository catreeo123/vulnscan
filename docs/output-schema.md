# vulnscan JSON Output Schema

Produced by `vulnscan scan --format json` and `vulnscan check --format json`.

## Versioning

The top-level `schemaVersion` field lets consumers guard against breaking wire-format changes.
**Major bumps only** — a new `schemaVersion` value signals a breaking change (removed or renamed fields). Additive changes (new optional fields) do not bump the version.

Current version: `"1"`

## Top-level shape

```json
{
  "schemaVersion": "1",
  "findings": [ ...Finding ],
  "warnings": [ "string" ]
}
```

`schemaVersion` — wire-format version. Pin consumers to this value; reject on mismatch.

`warnings` — non-fatal notices (e.g. skipped git-sourced deps, skipped npm-aliased deps, clock-skew detected, advisory sync page limit reached). Always present; empty array when no warnings.

## Finding

```json
{
  "name":    "lodash",
  "version": "4.17.20",
  "via":     "webpack",
  "advisory": { ...Advisory },
  "fix":     "4.17.21"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Package name |
| `version` | `string` | Installed version |
| `via` | `string \| undefined` | Direct dependency that pulled in this package. Absent when the vulnerable package is itself a direct dependency |
| `advisory` | `Advisory` | The advisory record this finding is derived from |
| `fix` | `string \| undefined` | First version that resolves the vulnerability. `undefined` means no fix is known — the package should be removed or replaced |

## Advisory

```json
{
  "id":          "CVE-2021-23337",
  "canonicalId": "GHSA-35jh-r3h4-6jhm",
  "type":        "cve",
  "packageName": "lodash",
  "ranges": [
    { "introduced": "0.0.0", "fixed": "4.17.21" }
  ],
  "severity": "high",
  "title":    "Command Injection in lodash",
  "url":      "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Primary identifier. `CVE-*` for vulnerabilities, `MAL-*` for supply chain signals |
| `canonicalId` | `string` | Preferred deduplication key. GHSA ID when available; falls back to `id` |
| `type` | `"cve" \| "mal"` | `cve` = CVE-backed vulnerability. `mal` = malicious package report (backdoor, exfiltration, typosquat) |
| `packageName` | `string` | Affected package name per the advisory source |
| `ranges` | `SemverRange[]` | Vulnerable version ranges |
| `severity` | `"critical" \| "high" \| "moderate" \| "low"` | CVSS-derived severity. When sources disagree, highest wins |
| `title` | `string` | Short description of the vulnerability or malicious behaviour |
| `url` | `string` | Canonical advisory URL (NVD for CVEs, GitHub Advisories for GHSAs) |

## SemverRange

```json
{ "introduced": "0.0.0", "fixed": "4.17.21" }
```

| Field | Type | Description |
|-------|------|-------------|
| `introduced` | `string \| undefined` | First affected version |
| `fixed` | `string \| undefined` | First non-affected version (exclusive upper bound) |
| `lastAffected` | `string \| undefined` | Last affected version (inclusive upper bound, used when no fix exists) |
| `rawRange` | `string \| undefined` | Raw semver expression from the source when structured fields are unavailable |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings matching `--fail-on` severities |
| `1` | One or more findings at a `--fail-on` severity |
