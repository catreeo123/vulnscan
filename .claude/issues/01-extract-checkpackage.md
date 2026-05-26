---
type: AFK
triage: ready
origin: A3 (post-tier4-synthesis architecture review, Strong recommendation)
---

# Extract `checkPackage` into `scanner.ts`

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — Group 2.A3.

## What to build

The `check` branch in `cli.ts` re-implements the scan pipeline inline (sync gate → query advisories → match → deduplicate → render). Extract that pipeline into a new exported function in `scanner.ts` so it lives next to `runScan` and any future change to Finding production touches one place.

End-to-end behavior: identical CLI output for `vulnscan check pkg@ver [--dir <path>]`. Internally, the check branch shrinks to ~10 lines: parse `pkg@ver`, open db, call `checkPackage(...)`, render result, exit.

Decision-rich shape (from architecture review):

```ts
type CheckInput = { name: string; version: string; db: Database.Database; config: Config }
type CheckResult = { findings: Finding[]; advisoryCount: number }
async function checkPackage(input: CheckInput): Promise<CheckResult>
```

`checkPackage` owns the `syncIfStale` call internally (mirrors `runScan`).

## Acceptance criteria

- [ ] `scanner.ts` exports `checkPackage(input: CheckInput): Promise<CheckResult>`.
- [ ] `cli.ts` check branch uses `checkPackage` exclusively; no inline pipeline.
- [ ] All 152 existing tests still pass with zero behavior change.
- [ ] At least one new unit test invokes `checkPackage` directly (no spawn) to prove the function is callable in isolation.
- [ ] `tsc --noEmit` clean.

## Blocked by

- None — can start immediately.
