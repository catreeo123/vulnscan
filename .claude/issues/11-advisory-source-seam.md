---
type: HITL
triage: design-needed
origin: A1 (post-tier4-synthesis architecture review, Strong but gated on real driver)
---

# AdvisorySource seam

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — Group 2.A1.

## What to build

The two advisory adapters (`osv-sync`, `github-advisory-sync`) share no interface. Both have a private `mapSeverity` implementation. The orchestrator hardcodes source names.

Architecture review proposes:

```ts
type AdvisorySource = {
  name: 'osv' | 'github' | string
  fullSync(db: Database.Database): Promise<{ imported: number; skipped: number; fullSyncStartedAt: number }>
  incrementalSync?(db: Database.Database, since: number): Promise<{ imported: number }>
}
```

Plus a shared `severity.ts` for `mapSeverity`. The orchestrator becomes a registry that iterates registered sources.

**This issue is explicitly gated**: do NOT implement until a third source (npm audit, Snyk, ClojARs equivalent, etc.) is concretely on the roadmap. With only two adapters, the seam is speculative and the deletion test fails — collapsing it back would only redistribute complexity, not concentrate it.

If a third source is requested AND this work is started, the in-flight branch should also extract `mapSeverity` into `severity.ts` as a prerequisite.

## Acceptance criteria

- [ ] Triggering condition met: a stakeholder has requested a third advisory source AND that source is on the next quarter's roadmap.
- [ ] `AdvisorySource` interface defined.
- [ ] Both existing adapters refactored to implement the interface.
- [ ] Shared `mapSeverity` extracted to `severity.ts`.
- [ ] `sync-orchestrator` becomes a registry.
- [ ] The third source ships in the same PR as the seam (validates that the seam earns its keep).

If the triggering condition never materializes, close this issue with an ADR rejecting the seam.

## Blocked by

- External: real third-source driver on the roadmap.
