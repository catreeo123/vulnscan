import { describe, it, expect } from 'vitest'
import { parseLockfile } from './lockfile-parser.js'

const v2Fixture = JSON.stringify({
  name: 'my-app',
  lockfileVersion: 2,
  packages: {
    '': {
      dependencies: { lodash: '^4.17.21' },
    },
    'node_modules/lodash': {
      version: '4.17.21',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
    },
  },
})

const v2WithTransitive = JSON.stringify({
  name: 'my-app',
  lockfileVersion: 2,
  packages: {
    '': { dependencies: { lodash: '^4.17.21' } },
    'node_modules/lodash': {
      version: '4.17.21',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
      dependencies: { semver: '^7.0.0' },
    },
    'node_modules/semver': {
      version: '7.6.0',
      resolved: 'https://registry.npmjs.org/semver/-/semver-7.6.0.tgz',
    },
  },
})

describe('parseLockfile', () => {
  it('returns dep list from v2 lockfile', () => {
    const { deps } = parseLockfile(v2Fixture)
    expect(deps).toContainEqual({ name: 'lodash', version: '4.17.21' })
  })

  it('includes transitive deps, not just direct', () => {
    const { deps } = parseLockfile(v2WithTransitive)
    expect(deps).toContainEqual({ name: 'lodash', version: '4.17.21' })
    expect(deps).toContainEqual({ name: 'semver', version: '7.6.0' })
  })

  it('handles v3 lockfile format including nested node_modules paths', () => {
    const v3Fixture = JSON.stringify({
      name: 'my-app',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { foo: '^1.0.0' } },
        'node_modules/foo': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz',
        },
        'node_modules/foo/node_modules/bar': {
          version: '2.0.0',
          resolved: 'https://registry.npmjs.org/bar/-/bar-2.0.0.tgz',
        },
      },
    })

    const { deps } = parseLockfile(v3Fixture)

    expect(deps).toContainEqual({ name: 'foo', version: '1.0.0' })
    expect(deps).toContainEqual({ name: 'bar', version: '2.0.0' })
  })

  it('resolves npm alias deps to target package and emits an informational warning', () => {
    const fixture = JSON.stringify({
      name: 'my-app',
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { 'lodash-alias': 'npm:lodash@4.17.21', semver: '^7.0.0' } },
        'node_modules/lodash-alias': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          name: 'lodash',
        },
        'node_modules/semver': {
          version: '7.6.0',
          resolved: 'https://registry.npmjs.org/semver/-/semver-7.6.0.tgz',
        },
      },
    })

    const { deps, warnings } = parseLockfile(fixture)

    // alias is resolved to the target package (lodash), not skipped
    expect(deps).toContainEqual(expect.objectContaining({ name: 'lodash', version: '4.17.21', via: 'lodash-alias' }))
    expect(deps).not.toContainEqual(expect.objectContaining({ name: 'lodash-alias' }))
    expect(deps).toContainEqual({ name: 'semver', version: '7.6.0' })
    // warning is informational (not incomplete)
    expect(warnings).toHaveLength(1)
    expect(warnings[0].class).toBe('informational')
    expect(warnings[0].message).toMatch(/lodash-alias/)
  })

  it('malformed package.json emits an informational warning (not incomplete) and does not crash', () => {
    const { deps, warnings } = parseLockfile(v2Fixture, 'not valid json {{{')
    expect(deps.length).toBeGreaterThan(0)
    const w = warnings.find((w) => /package\.json/.test(w.message))
    expect(w).toBeDefined()
    // package.json feeds ONLY ancestry (the `via` display field); deps come entirely from the
    // lockfile. So detection coverage is complete — this must be informational (exit 0/1), not
    // incomplete (exit 2 = data may be missing).
    expect(w!.class).toBe('informational')
  })

  it('returns empty deps and a warning for v1 lockfile (no packages key)', () => {
    const v1Fixture = JSON.stringify({ lockfileVersion: 1, dependencies: { foo: { version: '1.0.0' } } })
    const { deps, warnings } = parseLockfile(v1Fixture)
    expect(deps).toEqual([])
    expect(warnings.some((w) => /v1|v2\/v3|npm install/.test(w.message))).toBe(true)
  })

  it('throws a descriptive error for malformed lockfile JSON', () => {
    expect(() => parseLockfile('{not json')).toThrow(/is not valid JSON/)
  })

  it('skips git-sourced deps and emits one warning per skipped dep', () => {
    const fixture = JSON.stringify({
      name: 'my-app',
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { 'my-git-pkg': 'github:user/repo', lodash: '^4.17.21' } },
        'node_modules/my-git-pkg': {
          version: '1.0.0',
          resolved: 'git+https://github.com/user/repo.git#abc123',
        },
        'node_modules/lodash': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
        },
      },
    })

    const { deps, warnings } = parseLockfile(fixture)

    expect(deps).not.toContainEqual(expect.objectContaining({ name: 'my-git-pkg' }))
    expect(deps).toContainEqual({ name: 'lodash', version: '4.17.21' })
    expect(warnings).toHaveLength(1)
    expect(warnings[0].message).toMatch(/my-git-pkg/)
  })
})
