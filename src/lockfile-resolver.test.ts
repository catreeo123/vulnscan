import { describe, it, expect } from 'vitest'
import { resolveEntry } from './lockfile-resolver.js'
import type { PackageEntry } from './lockfile-resolver.js'

describe('resolveEntry', () => {
  // ── Plain transitive dep ────────────────────────────────────────────────────
  it('plain dep: returns dep with name derived from path', () => {
    const result = resolveEntry('node_modules/lodash', {
      version: '4.17.21',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
    })
    expect(result.dep).toEqual({ name: 'lodash', version: '4.17.21' })
    expect(result.warning).toBeUndefined()
  })

  it('plain dep: nested node_modules path uses last segment as name', () => {
    const result = resolveEntry('node_modules/foo/node_modules/bar', {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/bar/-/bar-2.0.0.tgz',
    })
    expect(result.dep).toEqual({ name: 'bar', version: '2.0.0' })
    expect(result.warning).toBeUndefined()
  })

  it('plain dep: multiple node_modules segments (deeply nested)', () => {
    const result = resolveEntry('node_modules/a/node_modules/b/node_modules/c', {
      version: '3.0.0',
    })
    expect(result.dep).toEqual({ name: 'c', version: '3.0.0' })
  })

  // ── Workspace via link:true ─────────────────────────────────────────────────
  it('workspace via link:true: emits dep with local:true', () => {
    const result = resolveEntry('packages/my-lib', { version: '1.0.0', link: true, name: 'my-lib' })
    expect(result.dep).toEqual({ name: 'my-lib', version: '1.0.0', local: true })
    expect(result.warning).toBeUndefined()
  })

  it('workspace via link:true: uses path segment as name when pkg.name absent', () => {
    const result = resolveEntry('packages/my-lib', { version: '2.0.0', link: true })
    expect(result.dep).toMatchObject({ local: true, version: '2.0.0' })
    expect(result.dep?.name).toBeTruthy()
  })

  // ── Workspace via root glob ─────────────────────────────────────────────────
  it('workspace via glob: path matching packages/* glob emits local:true dep', () => {
    const result = resolveEntry(
      'packages/frontend',
      { version: '1.0.0', name: 'frontend' },
      ['packages/*'],
    )
    expect(result.dep).toEqual({ name: 'frontend', version: '1.0.0', local: true })
    expect(result.warning).toBeUndefined()
  })

  it('workspace via glob: does NOT match node_modules path even if glob would', () => {
    // a node_modules entry cannot be a workspace entry even if some glob matches
    const result = resolveEntry(
      'node_modules/lodash',
      { version: '4.17.21', name: 'lodash' },
      ['node_modules/*'],
    )
    // should be treated as plain dep, not workspace
    expect(result.dep).toEqual({ name: 'lodash', version: '4.17.21' })
    expect(result.dep?.local).toBeUndefined()
  })

  it('workspace via glob: apps/* pattern matches nested app dir', () => {
    const result = resolveEntry(
      'apps/dashboard',
      { version: '0.1.0', name: 'dashboard' },
      ['apps/*'],
    )
    expect(result.dep).toMatchObject({ local: true })
  })

  // ── npm alias ───────────────────────────────────────────────────────────────
  it('npm alias: emits dep with target name and informational warning', () => {
    const result = resolveEntry(
      'node_modules/lodash-alias',
      { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', name: 'lodash' },
    )
    expect(result.dep).toEqual({ name: 'lodash', version: '4.17.21', via: 'lodash-alias' })
    expect(result.warning).toBeDefined()
    expect(result.warning?.class).toBe('informational')
    expect(result.warning?.message).toMatch(/lodash-alias/)
  })

  it('npm alias: warning mentions alias key', () => {
    const result = resolveEntry(
      'node_modules/my-alias',
      { version: '1.0.0', name: 'real-package' },
    )
    expect(result.warning?.message).toMatch(/my-alias/)
    expect(result.warning?.class).toBe('informational')
  })

  it('npm alias with missing version: emits incomplete, not a dep that can never match', () => {
    // The alias branch fabricated version '0.0.0' when version was absent, producing a
    // scannable Dep that matchAffected can never satisfy → the aliased package silently
    // reports clean (exit 0) behind only an informational warning. Surface as incomplete
    // (exit 2), like the plain-dep empty-version guard.
    const result = resolveEntry(
      'node_modules/lodash-alias',
      { name: 'lodash' } as PackageEntry,
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
    expect(result.warning?.message).toMatch(/lodash-alias/)
  })

  it('npm alias with empty version string: emits incomplete', () => {
    const result = resolveEntry(
      'node_modules/lodash-alias',
      { name: 'lodash', version: '' } as PackageEntry,
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
  })

  // ── git-source dep ──────────────────────────────────────────────────────────
  it('git+: emits no dep, incomplete warning', () => {
    const result = resolveEntry(
      'node_modules/my-git-pkg',
      { version: '1.0.0', resolved: 'git+https://github.com/user/repo.git#abc123' },
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning).toBeDefined()
    expect(result.warning?.class).toBe('incomplete')
    expect(result.warning?.message).toMatch(/my-git-pkg/)
  })

  it('git://: emits no dep, incomplete warning', () => {
    const result = resolveEntry(
      'node_modules/another-git',
      { version: '0.1.0', resolved: 'git://github.com/user/repo.git' },
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
  })

  // ── github:/bitbucket:/gitlab: shorthand git deps ───────────────────────────
  it('github: resolved prefix: emits no dep, incomplete warning', () => {
    const result = resolveEntry(
      'node_modules/my-gh-pkg',
      { version: '1.0.0', resolved: 'github:org/repo#abc123' },
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning).toBeDefined()
    expect(result.warning?.class).toBe('incomplete')
    expect(result.warning?.message).toMatch(/my-gh-pkg/)
  })

  it('bitbucket: resolved prefix: emits no dep, incomplete warning', () => {
    const result = resolveEntry(
      'node_modules/my-bb-pkg',
      { version: '1.0.0', resolved: 'bitbucket:org/repo#abc123' },
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
  })

  it('gitlab: resolved prefix: emits no dep, incomplete warning', () => {
    const result = resolveEntry(
      'node_modules/my-gl-pkg',
      { version: '1.0.0', resolved: 'gitlab:org/repo#abc123' },
    )
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
  })

  // ── No version → skip silently ──────────────────────────────────────────────
  it('entry without version: returns empty result', () => {
    const result = resolveEntry('node_modules/virtual', {} as PackageEntry)
    expect(result.dep).toBeUndefined()
    expect(result.warning).toBeUndefined()
  })

  // ── Empty version → incomplete (not a silent unmatchable dep) ─────────────────
  it('entry with an empty version string: emits incomplete, not a dep that can never match', () => {
    // version "" is not undefined, so the plain-dep branch used to emit { name, version: '' }.
    // matchAffected('', range) is always false → a vulnerable package silently reports clean
    // (exit 0). An un-checkable version must surface as incomplete (exit 2) instead.
    const result = resolveEntry('node_modules/foo', { version: '' } as PackageEntry)
    expect(result.dep).toBeUndefined()
    expect(result.warning?.class).toBe('incomplete')
  })

  // ── Robustness: non-string workspace glob must not crash the scan ─────────────
  it('non-string workspace glob entry does not throw (crafted/malformed lockfile)', () => {
    // rootWorkspaces is typed string[] but comes from untrusted lockfile JSON. A non-string
    // element (e.g. "workspaces": [123]) reaching matchesGlob().split() throws an uncaught
    // TypeError, which the CLI's top-level catch maps to exit 1 ("findings") — misreporting a
    // crash as a scan result. The matcher must skip non-string globs instead.
    expect(() =>
      resolveEntry('packages/foo', { version: '1.0.0', name: 'foo' }, [123 as unknown as string]),
    ).not.toThrow()
  })

  it('ignores non-string globs but still honors valid string globs alongside them', () => {
    const result = resolveEntry(
      'packages/frontend',
      { version: '1.0.0', name: 'frontend' },
      [123 as unknown as string, 'packages/*'],
    )
    expect(result.dep).toEqual({ name: 'frontend', version: '1.0.0', local: true })
  })

  // ── Supply-chain: lockfile-only tamper must not hide a real dep via link:true ─
  it('does NOT treat a node_modules entry as local when link:true is paired with a version (lockfile tamper)', () => {
    // A genuine npm workspace symlink entry carries link:true and NO version. An attacker can add
    // link:true to a real registry dep (which keeps its version + resolved tarball) to make
    // vulnscan mark it local and skip it — a silent false-clean (exit 0). Only a versionless link
    // entry is a real symlink; a link entry that also has a concrete version is a tamper signal.
    const result = resolveEntry('node_modules/left-pad', {
      version: '0.0.1',
      resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-0.0.1.tgz',
      link: true,
    })
    expect(result.dep).toEqual({ name: 'left-pad', version: '0.0.1' })
    expect(result.dep?.local).toBeUndefined()
  })

  it('still treats a versionless link entry as a local workspace (genuine npm symlink — no regression)', () => {
    const result = resolveEntry('node_modules/my-lib', { link: true, name: 'my-lib' })
    expect(result.dep?.local).toBe(true)
  })
})
