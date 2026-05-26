## What to build

Reduce subsequent GitHub Advisory sync cost from 63 pages to 1–3 pages by filtering advisories updated since the last sync.

The GitHub Advisory sync function gains an optional `since?: number` (Unix timestamp ms) parameter. When provided, the initial API URL includes an `updated` filter. When absent, the full unfiltered URL is used.

The sync orchestrator reads `getLastSyncedAt(db, 'github')` and passes it as `since`. On first sync (null), no `since` is passed and a full sync runs automatically.

OSV sync is unchanged (OSV has no per-advisory update API).

**Implementation note — verify API filter syntax before coding:**

The current base URL is:
```
/advisories?type=reviewed&ecosystem=npm&per_page=100
```

Run the following curl to confirm the `updated` parameter syntax before implementing:
```bash
curl -s "https://api.github.com/advisories?type=reviewed&ecosystem=npm&per_page=1&updated=>=2025-01-01T00:00:00Z" \
  -H "Accept: application/vnd.github+json" | head -c 500
```

Expected: a JSON array with one item. If it returns an error or all items, try alternate syntax (`updated=>2025-01-01`, `updated[gte]=2025-01-01`). Use whichever works.

## Acceptance criteria

- [ ] Verified working `updated` filter syntax via curl before coding
- [ ] Subsequent sync (prior timestamp exists) appends a verified `updated` filter to the initial URL only; cursor pagination continues normally from there
- [ ] First sync (no prior timestamp) runs full unfiltered sync
- [ ] `since` is read from `getLastSyncedAt(db, 'github')` in the sync orchestrator
- [ ] OSV sync behaviour is unchanged
- [ ] Existing e2e test suite passes

## Blocked by

None - can start immediately
