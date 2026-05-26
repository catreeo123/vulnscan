---
type: AFK
triage: ready
origin: N3 (scrutinize report, deferred from Group 1)
---

# Add summary line to `check` command output

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — scrutinize N3.

## What to build

The `scan` command writes a summary line to stderr before rendering findings:

```
Checked 47 packages against 12380 advisories
```

The `check` command renders findings directly with no equivalent context. Add the same shape for `check` (one package against advisory count):

```
Checked lodash@4.17.20 against 12380 advisories
```

Use the `advisoryCount` field already returned by `checkPackage` (from #1). Format-aware: stderr only, NOT in JSON output (`--format json`).

## Acceptance criteria

- [ ] Running `vulnscan check pkg@ver` writes the summary line to stderr before the findings table.
- [ ] Running `vulnscan check pkg@ver --format json` writes ONLY clean JSON to stdout (no contamination of the JSON output channel).
- [ ] A new e2e test asserts the stderr line is present in table mode and absent in JSON mode.
- [ ] All existing tests still pass.

## Blocked by

- #1 (Extract `checkPackage`) — uses the `advisoryCount` field from `CheckResult`.
