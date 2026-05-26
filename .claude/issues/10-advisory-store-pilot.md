---
type: HITL
triage: design-needed
origin: A2 (post-tier4-synthesis architecture review, Strong but gated)
---

# AdvisoryStore repository pilot

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — Group 2.A2.

## What to build

`local-db.ts` exports nine functions spanning three concerns (schema/migration, Advisory persistence, sync metadata). Tests can only use a real SQLite file. Architecture review proposes introducing an `AdvisoryStore` interface plus an in-memory adapter, hiding migrations behind `openStore`.

This is a **pilot** issue, not a full migration. The architecture review explicitly gates A2 on "proof-of-value": convert 2-3 existing tests to use the in-memory store and check whether they actually become simpler. If yes, file the broader migration as a follow-up. If no, write an ADR rejecting the seam.

Decision-rich interface from the architecture review:

```ts
type AdvisoryStore = {
  getForPackage(name: string): Advisory[]
  upsert(advisory: Advisory): void
  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void
  count(): number
  pruneStale(fullSyncStartedAt: number, gracePeriodMs: number): void
  getLastSyncedAt(source: string): number | null
  setLastSyncedAt(source: string, ts: number): void
  close(): void
}
function openStore(path?: string): AdvisoryStore
```

## Acceptance criteria

- [ ] `AdvisoryStore` interface defined; `openStore` returns a SQLite-backed adapter using the current `local-db.ts` implementation.
- [ ] `InMemoryAdvisoryStore` adapter exists.
- [ ] 2-3 existing tests converted to use the in-memory adapter and demonstrably shorter (or document the inverse outcome with concrete counts).
- [ ] Decision documented as an ADR: either "proceed with full migration" or "reject, raw `Database.Database` is fine".

## Blocked by

- #1 (Extract `checkPackage`) — the cleaner store boundary emerges only after the inline pipeline moves out of `cli.ts`.
