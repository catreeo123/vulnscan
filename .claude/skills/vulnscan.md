# /vulnscan — Vulnerability Scan

Scan a project's npm dependencies for vulnerabilities and explain every finding in plain language.

## Invocation

```
/vulnscan [path]
```

`path` is optional. Defaults to the current working directory.

## Step 1 — Prerequisite check

Run `which vulnscan`. If the command is not found, tell the user:

> **vulnscan is not installed.** Install it by running the following in the vulnscan repo:
> ```bash
> npm install && npm run build && npm link
> ```

Stop. Do not proceed.

## Step 2 — Run the scan

```bash
vulnscan scan <path> --format json
```

If the command exits non-zero with a message about `package-lock.json not found`, tell the user:

> **No package-lock.json found** at `<path>`. vulnscan requires a `package-lock.json` to scan the dependency tree.

Stop. Do not proceed.

## Step 3 — Parse JSON output

The output shape is documented in `docs/output-schema.md`. Top level:

```json
{ "findings": [...], "warnings": [...] }
```

## Step 4 — Display results

### Warnings

If `warnings` is non-empty, list them first:

**Warnings**
- <each warning string>

Warnings are non-fatal. Continue to findings.

### Zero findings

If `findings` is empty:

> ✓ No vulnerabilities found.

### Findings

Group findings by severity in this order: **critical → high → moderate → low**.

For each finding, show all of the following:

1. **Package** — `name@version`. If the `via` field is present: `name@version (via direct-dep)`.

2. **Advisory** — `advisory.id`: `advisory.title`

3. **Type signal** — if `advisory.type === 'mal'`, prepend this block before the fix line:
   > ⚠ **Malicious Package** — This is a supply chain attack (backdoor / data exfiltration / protestware), not a code vulnerability. Treat with urgency regardless of severity rating.

4. **Fix** — one of:
   - `fix` is a version string:
     - Show: `Fix: upgrade to <fix>`
     - If the major version of `fix` is greater than the major version of `version` (compare the integer before the first `.`): also show `⚠ Major version bump — likely breaking changes`
   - `fix` is absent or `undefined`:
     - Show: `No fix available. Consider removing or replacing this package.`

5. **Reference** — `advisory.url`

### Breaking change detection — exact rule

Extract the major version as the integer before the first `.`:
- `"1.4.3"` → major `1`
- `"2.0.0"` → major `2`
- `"4.17.21"` → major `4`

If `major(fix) > major(version)` → flag breaking. Do not infer from the advisory title.

## Example output

```
**Warnings**
- git-sourced dep skipped: my-git-dep (version unknown — cannot match ranges)

**Critical (1)**

evil-pkg@1.0.0
⚠ Malicious Package — This is a supply chain attack (backdoor / data exfiltration / protestware), not a code vulnerability. Treat with urgency regardless of severity rating.
MAL-2024-1234: Malicious package: data exfiltration
No fix available. Consider removing or replacing this package.
https://osv.dev/vulnerability/MAL-2024-1234

**High (1)**

lodash@4.17.20 (via webpack)
CVE-2021-23337: Command Injection in lodash
Fix: upgrade to 4.17.21
https://nvd.nist.gov/vuln/detail/CVE-2021-23337

**High (1)**

some-pkg@1.0.0
CVE-2024-UPGRADE: Prototype pollution
Fix: upgrade to 2.0.0
⚠ Major version bump — likely breaking changes
https://example.com/cve
```
