## What to build

Replace the flat `renderTable` function with a `renderGrouped` function that organises findings by severity then by package. Each severity level gets a coloured header with a finding count. Each package appears once per severity group with all its CVEs listed beneath it.

Each CVE line shows: advisory ID, title (truncated to 60 chars), optional `→ fix: ≥<version>` (first `fixed` value found across all structured `ranges[]` entries, in array order), and a canonical URL (`CVE-*` → NVD, `GHSA-*` → GitHub Advisory).

**This issue also owns the type additions** required by Issue #2:
```
Dep     = { name: string; version: string; via?: string }
Finding = { name: string; version: string; via?: string; advisory: Advisory }
```

The `via` field is optional at render time — shown on the package line when present, silently omitted when absent. Issue #2 (ancestry tracking) will populate it once it is unblocked by this issue.

The `renderTable` function is **deleted** (replaced entirely, not kept unused).

The `renderJson` function gains `via` and `fix` fields in its output for CI/CD consumption.

## Acceptance criteria

- [ ] `Dep` and `Finding` types gain `via?: string` field in `src/types.ts`
- [ ] Output groups findings under CRITICAL / HIGH / MODERATE / LOW headers in that order
- [ ] Each severity header shows the count of findings in that group
- [ ] Each package appears once per group with all its CVEs indented beneath it
- [ ] CVE lines include advisory ID, ≤60-char title, canonical URL
- [ ] `→ fix: ≥<version>` shown using the first `ranges[].fixed` value found (array order); omitted silently when no `fixed` exists
- [ ] `[via <root-dep>]` shown on package line when `via` field is present
- [ ] `--format json` output includes `via` and `fix` fields
- [ ] Empty findings renders clean "no findings" message
- [ ] `renderTable` is deleted (not just unused)
- [ ] CLI calls `renderGrouped` instead of `renderTable`
- [ ] Unit tests cover: severity grouping order, via/fix annotation presence/absence, canonical URL format (CVE → NVD, GHSA → GitHub), empty findings

## Blocked by

None - can start immediately
