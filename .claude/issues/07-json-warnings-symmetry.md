---
type: HITL
triage: design-needed
origin: A4 (post-tier4-synthesis architecture review, Worth exploring)
---

# JSON renderer surfaces warnings

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — Group 2.A4.

## What to build

`renderGrouped` (table mode) writes warnings to stderr alongside the findings table. `renderJson` ignores warnings entirely — any consumer parsing JSON output loses the warning channel (e.g. "lockfile v1 not supported", "git-sourced dep skipped").

**Design decision needed** before implementation:

- (a) Change JSON output shape to a wrapper object: `{ findings: Finding[], warnings: string[] }`. Breaking change for any existing JSON consumer.
- (b) Add a new top-level key while preserving array-shape for findings: emit `{ findings: [...], warnings: [...] }` only when warnings are non-empty; emit the bare array when no warnings. Conditional shape is awkward to consume.
- (c) Emit warnings as a separate stream — e.g. a `--json-warnings` flag that routes them to a sidecar file or a second stdout chunk. Most flexible, most surface.

The current JSON consumer story is unknown — pick whichever shape best preserves forward compatibility with the unknown consumer set.

## Acceptance criteria

- [ ] An ADR captures the chosen shape and rejects the others with rationale.
- [ ] `renderJson` emits warnings per the chosen shape.
- [ ] Existing JSON tests update OR a JSON consumer doc explicitly notes the breaking change.
- [ ] A new test exercises a warning-bearing input (e.g. v1 lockfile) and asserts the warning appears in JSON output.

## Blocked by

- None to implement, but blocked on the **design decision** above.
