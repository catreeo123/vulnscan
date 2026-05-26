import { vi, it, expect, describe, beforeEach } from 'vitest'
import { syncIfStale } from './sync-orchestrator.js'
import { InMemoryAdvisoryStore } from './advisory-store-memory.js'

vi.mock('./sync-orchestrator.js', () => ({
  syncIfStale: vi.fn().mockResolvedValue(undefined),
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

  it('TEST 3: warnings from parser surface in result', async () => {
    // v1 lockfile — no `packages` key
    const v1Lockfile = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.20' } },
    })

    const result = await runScan({ lockfileContent: v1Lockfile, store, config: baseConfig })

    expect(result.findings).toHaveLength(0)
    expect(result.warnings.some((w) => w.includes('v1'))).toBe(true)
  })
})
