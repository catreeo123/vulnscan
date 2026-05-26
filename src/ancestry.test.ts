import { describe, it, expect } from 'vitest'
import { buildAncestryMap } from './ancestry.js'

// ── Behavior 1: Direct root dep is NOT in the returned map ───────────────────

describe('buildAncestryMap', () => {
  it('direct root dep is absent from the returned map', () => {
    const lockfile = {
      packages: {
        '': {},
        'node_modules/lodash': { version: '4.17.21' },
      },
    }
    const packageJson = { dependencies: { lodash: '^4.17.21' } }

    const map = buildAncestryMap(lockfile, packageJson)
    expect(map.has('lodash')).toBe(false)
  })

  // ── Behavior 2: One-level transitive dep ─────────────────────────────────

  it('one-level transitive: root → protobufjs → via = root name', () => {
    const lockfile = {
      packages: {
        '': {},
        'node_modules/dd-trace': {
          version: '4.0.0',
          dependencies: { protobufjs: '^7.0.0' },
        },
        'node_modules/protobufjs': { version: '7.2.4' },
      },
    }
    const packageJson = { dependencies: { 'dd-trace': '^4.0.0' } }

    const map = buildAncestryMap(lockfile, packageJson)
    expect(map.get('protobufjs')).toBe('dd-trace')
  })

  // ── Behavior 3: Multi-level chain ─────────────────────────────────────────

  it('multi-level chain: root → A → B → C, C via = root (not A or B)', () => {
    const lockfile = {
      packages: {
        '': {},
        'node_modules/root-pkg': {
          version: '1.0.0',
          dependencies: { 'pkg-a': '^1.0.0' },
        },
        'node_modules/pkg-a': {
          version: '1.0.0',
          dependencies: { 'pkg-b': '^1.0.0' },
        },
        'node_modules/pkg-b': {
          version: '1.0.0',
          dependencies: { 'pkg-c': '^1.0.0' },
        },
        'node_modules/pkg-c': { version: '1.0.0' },
      },
    }
    const packageJson = { dependencies: { 'root-pkg': '^1.0.0' } }

    const map = buildAncestryMap(lockfile, packageJson)
    expect(map.get('pkg-c')).toBe('root-pkg')
    expect(map.get('pkg-b')).toBe('root-pkg')
    expect(map.get('pkg-a')).toBe('root-pkg')
  })

  // ── Behavior 4: v1 lockfile (no packages key) → empty map ─────────────────

  it('v1 lockfile with no packages key returns empty map', () => {
    const lockfile = {
      dependencies: {
        lodash: { version: '4.17.21' },
      },
    }
    const packageJson = { dependencies: { lodash: '^4.17.21' } }

    const map = buildAncestryMap(lockfile, packageJson)
    expect(map.size).toBe(0)
  })

  // ── Behavior 5b: Nested node_modules does not corrupt hoisted pkg dep tracking ──

  it('nested bar@2 under app does not corrupt dep tracking of hoisted bar@1', () => {
    const lockfile = {
      packages: {
        '': {},
        'node_modules/bar': { version: '1.0.0', dependencies: { baz: '^1.0.0' } },
        'node_modules/baz': { version: '1.0.0' },
        'node_modules/app': { version: '1.0.0', dependencies: { bar: '^2.0.0' } },
        'node_modules/app/node_modules/bar': { version: '2.0.0', dependencies: { qux: '^1.0.0' } },
        'node_modules/qux': { version: '1.0.0' },
      },
    }
    const packageJson = { dependencies: { app: '^1.0.0', bar: '^1.0.0' } }

    const map = buildAncestryMap(lockfile as unknown as Record<string, unknown>, packageJson)
    // baz is a dep of hoisted bar (a root dep) → via 'bar'
    expect(map.get('baz')).toBe('bar')
    // qux is a dep of app's nested bar → via 'app'
    expect(map.get('qux')).toBe('app')
  })

  // ── Behavior 5: First root in declaration order wins ──────────────────────

  it('package reachable from two roots: first in declaration order wins', () => {
    const lockfile = {
      packages: {
        '': {},
        'node_modules/root-a': {
          version: '1.0.0',
          dependencies: { 'shared-pkg': '^1.0.0' },
        },
        'node_modules/root-b': {
          version: '1.0.0',
          dependencies: { 'shared-pkg': '^1.0.0' },
        },
        'node_modules/shared-pkg': { version: '1.0.0' },
      },
    }

    // root-a declared first → shared-pkg via root-a
    const packageJsonAFirst = { dependencies: { 'root-a': '^1.0.0', 'root-b': '^1.0.0' } }
    const mapAFirst = buildAncestryMap(lockfile, packageJsonAFirst)
    expect(mapAFirst.get('shared-pkg')).toBe('root-a')

    // root-b declared first → shared-pkg via root-b
    const packageJsonBFirst = { dependencies: { 'root-b': '^1.0.0', 'root-a': '^1.0.0' } }
    const mapBFirst = buildAncestryMap(lockfile, packageJsonBFirst)
    expect(mapBFirst.get('shared-pkg')).toBe('root-b')
  })
})
