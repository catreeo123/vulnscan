---
type: AFK
triage: ready
origin: F9 (extra-high-recall code-review, PLAUSIBLE — semantic drift introduced by M2)
---

# `onProgress` callback accuracy after batch transaction

## Parent

Post-Group-1 code-review.

## What to build

Pre-M2, the OSV `onProgress` callback fired after each individual advisory was persisted to the DB. Post-M2 (batch transaction), the callback fires while advisories accumulate in an in-memory array — the DB is still empty when `imported=500` is reported.

Two acceptable approaches; the implementer chooses:

1. **Fire after persistence.** Move the `onProgress` invocation out of the parse loop and into a chunked persistence loop, calling `batchUpsert` on every N advisories and emitting progress after each chunk. Preserves the original contract (`imported` means "persisted") at the cost of more transactions (N/500 instead of 1).

2. **Relabel.** Keep the single batch and rename the progress callback's count from `imported` to `parsed` (or similar) so it accurately reflects "rows queued for write". Update the type signature and any caller.

Pick whichever preserves the most useful observability signal. Document the choice in the inline change.

## Acceptance criteria

- [ ] Contract is unambiguous: either `imported` is back to "persisted" or the field name reflects "parsed/queued".
- [ ] A unit test verifies the chosen contract: read DB inside `onProgress`, assert row count matches the reported value (approach 1) OR assert the type signature now uses the new field name (approach 2).
- [ ] No regression in M2 performance (still one transaction or N≪10000).

## Blocked by

- None — can start immediately.
