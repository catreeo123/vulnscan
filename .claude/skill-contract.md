# Claude Code Skill — Contract Spec

Implementation guide for the vulnscan Claude Code Skill. When this skill is built, follow this contract exactly.

## Invocation

```
/vulnscan [path]
```

`path` is optional. Defaults to current working directory.

## What to run

```bash
vulnscan scan <path> --format json
```

If `vulnscan` is not on PATH: tell the user to run `npm install && npm run build && npm link` in the vulnscan repo, then stop.

If `package-lock.json` is missing in `<path>`: surface the error message from vulnscan and stop. Do not attempt to scan.

## Output behaviour

Parse the JSON output per `docs/output-schema.md`.

### Warnings

If `warnings` is non-empty, list them first under a "Warnings" heading. These are non-fatal — continue to findings. `warningDetails[].class` (`"incomplete"` vs `"informational"`) is available if you need to distinguish coverage-affecting warnings from purely informational ones — plain-text `warnings` is sufficient for display.

### Zero findings

State clearly: no vulnerabilities found. Include the count of packages scanned if available.

### Findings

Group by severity (critical → high → moderate → low). For each finding:

1. **Package** — `name@version` (plus `via <direct-dep>` if `via` is present)
2. **Advisory** — `advisory.id`: `advisory.title`
3. **Type signal** — if `advisory.type === 'mal'`: prepend a clear warning that this is a **malicious package** (backdoor / data exfiltration / supply chain attack), not a CVE vulnerability
4. **Fix** — one of:
   - `fix` is a version string: "Fix: upgrade to `<fix>`"
     - If `semver.major(fix) > semver.major(version)`: add "⚠ major version bump — likely breaking changes"
   - `fix` is undefined: "No fix available. Consider removing or replacing this package."
5. **URL** — `advisory.url` for reference

## Breaking change assessment

Use semver major comparison only:
- Parse major version from `version` field (e.g. `"1.4.3"` → `1`)
- Parse major version from `fix` field (e.g. `"2.0.0"` → `2`)
- If fix major > installed major: flag as likely breaking

Do not infer breaking changes from advisory title or description.

## Decisions recorded here

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Input | Optional path | Covers 95% of use; flags belong on CLI |
| Explanation depth | Contextual (severity + what + fix + breaking) | All data in JSON; no external fetch needed |
| No-fix message | State plainly, suggest remove/replace | No hallucination risk |
| Breaking change signal | Semver major bump only | Deterministic; advisory titles describe vuln, not fix API impact |
| Skill contract location | `.claude/skill-contract.md` | Internal guidance, not user-facing docs |

See also: `docs/output-schema.md` for the full JSON field reference.
