---
type: HITL
triage: design-needed
origin: N7 (scrutinize report, deferred from Group 1)
---

# SQLite PRAGMA tuning (cache_size, mmap_size, synchronous)

## Parent

`/home/win/.claude/plans/post-tier4-synthesis.md` — scrutinize N7.

## What to build

`openDb` currently sets only `journal_mode = WAL`. Common opportunities to investigate:

- `synchronous = NORMAL` (vs default FULL): WAL mode + NORMAL is the SQLite-recommended pairing; faster commits, durability preserved across application crashes (only OS-level power-loss can corrupt). Likely safe for a local advisory cache where re-syncing is cheap.
- `cache_size = -64000` (~64MB): bigger page cache reduces I/O on the 12k+ advisory queries.
- `mmap_size = 268435456` (256MB): memory-mapped reads can speed up large scans.
- `temp_store = MEMORY`: avoids temp file on group-by queries.

**Profile data needed** before changing anything. Pure speculation without benchmarks invites a perf regression on small DBs or constrained hosts.

## Acceptance criteria

- [ ] Before-and-after wall-time numbers for `vulnscan update` (full OSV sync) and `vulnscan scan` against the demo fixture, on a representative host.
- [ ] Each PRAGMA is added independently (one commit per PRAGMA) so a regression can be bisected.
- [ ] Document the chosen settings inline with a comment explaining each tradeoff.
- [ ] No PRAGMA that breaks durability beyond the WAL + NORMAL pairing is added without an ADR.

## Blocked by

- None to implement, but blocked on **profile data collection**.
