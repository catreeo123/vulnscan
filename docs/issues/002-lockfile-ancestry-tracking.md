## What to build

Populate the `via?: string` field (added to `Dep` and `Finding` by Issue #1) so the grouped output renderer can display which direct root dependency transitively pulls in each vulnerable package.

A new module computes ancestry:
1. Reads root `dependencies`, `devDependencies`, `optionalDependencies` to identify direct root deps
2. Builds a forward dep map from each package's `dependencies` field in the lockfile (`packages` section)
3. Runs BFS from each root dep in **`package.json` declaration order** (dependencies before devDependencies before optionalDependencies; within each section, in key order). First BFS to claim a package wins.
4. Returns `Map<packageName, rootDepName>`; packages that are root deps themselves are absent (no `via` needed)

Only operates on v2/v3 lockfile format (has `packages[path].dependencies`). v1 lockfiles produce no ancestry data; `via` stays undefined for all packages.

The `via` value flows: lockfile parser populates it → range matcher copies it unchanged → findings display it.

## Acceptance criteria

- [ ] One-level transitive dep: `via` = direct root dep that owns it
- [ ] Multi-level chain (root → A → B → C): C's `via` = root dep (not A or B)
- [ ] Package claimed by multiple root deps: first BFS in declaration order wins, output is deterministic
- [ ] Direct root dep: no `via` annotation (absent from map)
- [ ] v1 lockfile: all `via` fields undefined
- [ ] `via` flows unchanged from lockfile parser through range matcher to findings
- [ ] Unit tests use lockfile JSON fixtures (no network, no DB)

## Blocked by

- Issue #1 (type changes for `via` on `Dep` and `Finding` live there)
