import { vi, it, expect, describe, beforeEach } from 'vitest'
import { syncIfStale } from './sync-orchestrator.js'
import { InMemoryAdvisoryStore } from './advisory-store-memory.js'

vi.mock('./sync-orchestrator.js', () => ({
  syncIfStale: vi.fn().mockResolvedValue([]),
}))

// imported after mock is set up
const { runScan, checkPackage } = await import('./scanner.js')

let store: InMemoryAdvisoryStore

beforeEach(() => {
  store = new InMemoryAdvisoryStore()
})

const baseConfig = { failOn: ['critical' as const], stalenessHours: 24 }

// Lockfile with root-only entry (no real packages)
const emptyLockfile = JSON.stringify({
  lockfileVersion: 2,
  packages: { '': {} },
})

describe('checkPackage', () => {
  it('TEST C1: vulnerable package → finding returned with correct advisoryCount', async () => {
    store.upsert({
      id: 'CVE-TEST-C01',
      canonicalId: 'GHSA-0000-0000-0C01',
      type: 'cve',
      packageName: 'express',
      ranges: [{ introduced: '0', fixed: '4.19.0' }],
      severity: 'high',
      title: 'Open Redirect',
      url: 'https://github.com/advisories/GHSA-0000-0000-0C01',
    })

    vi.mocked(syncIfStale).mockClear()
    const result = await checkPackage({ name: 'express', version: '4.18.0', store, config: baseConfig })

    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].name).toBe('express')
    expect(result.advisoryCount).toBe(1)
    expect(syncIfStale).toHaveBeenCalledWith(store, baseConfig.stalenessHours * 60 * 60 * 1000)
  })

  it('TEST C2: non-vulnerable version → no findings', async () => {
    store.upsert({
      id: 'CVE-TEST-C02',
      canonicalId: 'GHSA-0000-0000-0C02',
      type: 'cve',
      packageName: 'express',
      ranges: [{ introduced: '0', fixed: '4.19.0' }],
      severity: 'high',
      title: 'Open Redirect',
      url: 'https://github.com/advisories/GHSA-0000-0000-0C02',
    })

    const result = await checkPackage({ name: 'express', version: '4.19.1', store, config: baseConfig })

    expect(result.findings).toHaveLength(0)
    expect(result.advisoryCount).toBe(1)
  })

  it('TEST C3: unknown package → no findings', async () => {
    const result = await checkPackage({ name: 'some-unknown-pkg', version: '1.0.0', store, config: baseConfig })

    expect(result.findings).toHaveLength(0)
    expect(result.advisoryCount).toBe(0)
  })
})

// ─── D5T: noSync / offline mode ──────────────────────────────────────────────

describe('D5T: noSync flag skips syncIfStale', () => {
  it('runScan with noSync=true does not call syncIfStale', async () => {
    vi.mocked(syncIfStale).mockClear()
    await runScan({ lockfileContent: emptyLockfile, store, config: baseConfig, noSync: true })
    expect(syncIfStale).not.toHaveBeenCalled()
  })

  it('checkPackage with noSync=true does not call syncIfStale', async () => {
    vi.mocked(syncIfStale).mockClear()
    await checkPackage({ name: 'lodash', version: '4.17.20', store, config: baseConfig, noSync: true })
    expect(syncIfStale).not.toHaveBeenCalled()
  })

  it('runScan with noSync=true emits informational warning when cursors are null (never synced)', async () => {
    // InMemoryAdvisoryStore returns null for getLastSyncedAt by default
    const result = await runScan({ lockfileContent: emptyLockfile, store, config: baseConfig, noSync: true })
    expect(result.warnings.some((w) => w.class === 'informational')).toBe(true)
    expect(result.warnings.some((w) => w.message.includes('never been synced'))).toBe(true)
  })

  it('runScan with noSync=true emits informational warning when cursors are older than 7 days', async () => {
    const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000
    store.setLastSyncedAt('osv', eightDaysAgo)
    store.setLastSyncedAt('github', eightDaysAgo)
    const result = await runScan({ lockfileContent: emptyLockfile, store, config: baseConfig, noSync: true })
    expect(result.warnings.some((w) => w.class === 'informational')).toBe(true)
  })

  it('runScan with noSync=true emits no staleness warning when cursors are fresh', async () => {
    store.setLastSyncedAt('osv', Date.now())
    store.setLastSyncedAt('github', Date.now())
    const result = await runScan({ lockfileContent: emptyLockfile, store, config: baseConfig, noSync: true })
    expect(result.warnings.filter((w) => w.class === 'informational').length).toBe(0)
  })

  it('checkPackage with noSync=true includes warnings in result', async () => {
    // Cursors null → should warn
    const result = await checkPackage({ name: 'lodash', version: '4.17.20', store, config: baseConfig, noSync: true })
    expect(result.warnings).toBeDefined()
    expect(result.warnings.some((w) => w.class === 'informational')).toBe(true)
  })
})

describe('runScan', () => {
  it('TEST 1: empty lockfile → empty findings, advisoryCount reflects seeded DB', async () => {
    store.upsert({
      id: 'CVE-TEST-001',
      canonicalId: 'GHSA-0000-0000-0001',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Test advisory',
      url: 'https://github.com/advisories/GHSA-0000-0000-0001',
    })

    const result = await runScan({ lockfileContent: emptyLockfile, store, config: baseConfig })

    expect(result.findings).toHaveLength(0)
    expect(result.advisoryCount).toBe(1)
  })

  it('TEST 2: vulnerable package → finding returned', async () => {
    store.upsert({
      id: 'CVE-TEST-002',
      canonicalId: 'GHSA-0000-0000-0002',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Prototype Pollution',
      url: 'https://github.com/advisories/GHSA-0000-0000-0002',
    })

    const lockfileContent = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/lodash': {
          version: '4.17.20',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
        },
      },
    })

    const result = await runScan({ lockfileContent, store, config: baseConfig })

    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].name).toBe('lodash')
  })

  it('TEST 4: malformed lockfile rejects with descriptive error before any sync', async () => {
    await expect(
      runScan({ lockfileContent: '{not json', store, config: baseConfig }),
    ).rejects.toThrow(/is not valid JSON/)
  })

  it('depCount excludes local workspace deps (fix: count only non-local deps)', async () => {
    const lockfileContent = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': { workspaces: ['packages/*'] },
        'packages/pkg-a': { version: '1.0.0', name: 'pkg-a' },
        'packages/pkg-b': { version: '1.0.0', name: 'pkg-b' },
        'packages/pkg-c': { version: '1.0.0', name: 'pkg-c' },
        'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz' },
        'node_modules/express': { version: '4.18.0', resolved: 'https://registry.npmjs.org/express/-/express-4.18.0.tgz' },
        'node_modules/axios': { version: '1.0.0', resolved: 'https://registry.npmjs.org/axios/-/axios-1.0.0.tgz' },
        'node_modules/react': { version: '18.0.0', resolved: 'https://registry.npmjs.org/react/-/react-18.0.0.tgz' },
        'node_modules/typescript': { version: '5.0.0', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.0.0.tgz' },
        'node_modules/vitest': { version: '1.0.0', resolved: 'https://registry.npmjs.org/vitest/-/vitest-1.0.0.tgz' },
        'node_modules/prettier': { version: '3.0.0', resolved: 'https://registry.npmjs.org/prettier/-/prettier-3.0.0.tgz' },
        'node_modules/eslint': { version: '8.0.0', resolved: 'https://registry.npmjs.org/eslint/-/eslint-8.0.0.tgz' },
        'node_modules/zod': { version: '3.0.0', resolved: 'https://registry.npmjs.org/zod/-/zod-3.0.0.tgz' },
        'node_modules/chalk': { version: '5.0.0', resolved: 'https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz' },
      },
    })

    const result = await runScan({ lockfileContent, store, config: baseConfig, noSync: true })

    // 3 local workspace deps (pkg-a, pkg-b, pkg-c) should NOT be counted
    // 10 external deps should be counted
    expect(result.depCount).toBe(10)
  })

  it('TEST 3: warnings from parser surface in result', async () => {
    // v1 lockfile — no `packages` key
    const v1Lockfile = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.20' } },
    })

    const result = await runScan({ lockfileContent: v1Lockfile, store, config: baseConfig })

    expect(result.findings).toHaveLength(0)
    expect(result.warnings.some((w) => w.message.includes('v1'))).toBe(true)
  })
})
