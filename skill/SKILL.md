---
name: vulnscan
description: Runs vulnscan against a Node.js project and reports npm dependency vulnerabilities with severity, fix guidance, and breaking-change flags. Use when the user asks to scan for vulnerabilities, check dependencies for CVEs, or run vulnscan on a project.
---

# vulnscan

## Quick start

```
/vulnscan [path]
```

`path` defaults to current working directory.

## Workflow

### 1. Run the scan

```bash
vulnscan scan <path> --format json
```

**If `vulnscan` is not on PATH:** Tell the user to run `npm install && npm run build && npm link` in the vulnscan repo. Stop — do not proceed.

**If scan exits with an error about missing `package-lock.json`:** Surface the error message exactly. Stop — do not attempt to scan.

### 2. Parse JSON output

Schema: `schemaVersion`, `findings[]`, `warnings[]`.

If `schemaVersion !== "1"`: warn the user the schema has changed and stop.

### 3. Report warnings (if any)

List under a **Warnings** heading before findings. Warnings are non-fatal — always continue to findings.

### 4. Report findings

**Zero findings:** State clearly no vulnerabilities found. Include packages scanned count if present in output.

**With findings:** Group by severity in this order: `critical → high → moderate → low`.

For each finding:

1. **Package** — `name@version`. Append `via <direct-dep>` if `via` field is present.
2. **Advisory** — `advisory.id`: `advisory.title`
3. **Malicious package** — if `advisory.type === "mal"`: add a prominent warning that this is a **malicious package** (backdoor / data exfiltration / supply chain attack), not a CVE.
4. **Fix:**
   - `fix` is a version string → "Fix: upgrade to `<fix>`". If `semver.major(fix) > semver.major(version)`: add "⚠ major version bump — likely breaking changes"
   - `fix` is absent → "No fix available. Consider removing or replacing this package."
5. **URL** — `advisory.url`

### Breaking change rule

Major version of `fix` > major version of `version` = flag as likely breaking. Use semver major only. Do not infer from advisory title or description.
