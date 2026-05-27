import { it, expect, describe, beforeEach } from 'vitest'
import { InMemoryAdvisoryStore } from './advisory-store-memory.js'
import type { Advisory } from './types.js'

const advisory: Advisory = {
  id: 'CVE-TEST-001',
  canonicalId: 'GHSA-0000-0000-0001',
  type: 'cve',
  packageName: 'lodash',
  ranges: [{ introduced: '0', fixed: '4.17.21' }],
  severity: 'high',
  title: 'Prototype Pollution',
  url: 'https://github.com/advisories/GHSA-0000-0000-0001',
}

describe('InMemoryAdvisoryStore', () => {
  let store: InMemoryAdvisoryStore

  beforeEach(() => {
    store = new InMemoryAdvisoryStore()
  })

  it('getForPackage returns empty array for unknown package', () => {
    expect(store.getForPackage('lodash')).toEqual([])
  })

  it('upsert then getForPackage returns the advisory', () => {
    store.upsert(advisory)
    expect(store.getForPackage('lodash')).toEqual([advisory])
  })

  it('upsert is idempotent — same id+package replaces, not appends', () => {
    store.upsert(advisory)
    store.upsert({ ...advisory, severity: 'critical' })
    const results = store.getForPackage('lodash')
    expect(results).toHaveLength(1)
    expect(results[0].severity).toBe('critical')
  })

  it('count returns 0 initially', () => {
    expect(store.count()).toBe(0)
  })

  it('count reflects upserted entries', () => {
    store.upsert(advisory)
    expect(store.count()).toBe(1)
    store.upsert({ ...advisory, id: 'CVE-TEST-002', canonicalId: 'GHSA-0000-0000-0002' })
    expect(store.count()).toBe(2)
  })

  it('getLastSyncedAt returns null before set', () => {
    expect(store.getLastSyncedAt('osv')).toBeNull()
  })

  it('setLastSyncedAt / getLastSyncedAt round-trips', () => {
    store.setLastSyncedAt('osv', 12345)
    expect(store.getLastSyncedAt('osv')).toBe(12345)
  })

  it('upsertFromFullSync stores advisory (same getForPackage behavior)', () => {
    store.upsertFromFullSync(advisory, Date.now())
    expect(store.getForPackage('lodash')).toEqual([advisory])
  })

  it('pruneStale removes advisories not seen in full sync before cutoff', () => {
    const t0 = 1000
    store.upsertFromFullSync(advisory, t0)
    // fullSyncStartedAt=2000, gracePeriod=0 → cutoff=2000 → t0=1000 < 2000 → pruned
    store.pruneStale(2000, 0)
    expect(store.getForPackage('lodash')).toEqual([])
  })

  it('pruneStale keeps advisory seen in current sync', () => {
    const t0 = 2000
    store.upsertFromFullSync(advisory, t0)
    store.pruneStale(t0, 0)
    expect(store.getForPackage('lodash')).toEqual([advisory])
  })

  it('close is a no-op (does not throw)', () => {
    expect(() => store.close()).not.toThrow()
  })

  it('D4T — getForPackage returns advisories sorted by canonical_id ASC, id ASC', () => {
    const advisories: Advisory[] = [
      { id: 'CVE-2024-0005', canonicalId: 'GHSA-zzzz-zzzz-zzzz', type: 'cve', packageName: 'lodash', ranges: [], severity: 'high', title: 'A', url: 'https://example.com' },
      { id: 'CVE-2024-0003', canonicalId: 'GHSA-mmmm-mmmm-mmmm', type: 'cve', packageName: 'lodash', ranges: [], severity: 'high', title: 'B', url: 'https://example.com' },
      { id: 'CVE-2024-0001', canonicalId: 'GHSA-aaaa-aaaa-aaaa', type: 'cve', packageName: 'lodash', ranges: [], severity: 'high', title: 'C', url: 'https://example.com' },
      { id: 'CVE-2024-0004', canonicalId: 'GHSA-pppp-pppp-pppp', type: 'cve', packageName: 'lodash', ranges: [], severity: 'high', title: 'D', url: 'https://example.com' },
      { id: 'CVE-2024-0002', canonicalId: 'GHSA-bbbb-bbbb-bbbb', type: 'cve', packageName: 'lodash', ranges: [], severity: 'high', title: 'E', url: 'https://example.com' },
    ]

    for (const a of advisories) {
      store.upsert(a)
    }

    const first = store.getForPackage('lodash')
    const second = store.getForPackage('lodash')

    expect(first.map(a => a.canonicalId)).toEqual(second.map(a => a.canonicalId))
    expect(first.map(a => a.canonicalId)).toEqual([
      'GHSA-aaaa-aaaa-aaaa',
      'GHSA-bbbb-bbbb-bbbb',
      'GHSA-mmmm-mmmm-mmmm',
      'GHSA-pppp-pppp-pppp',
      'GHSA-zzzz-zzzz-zzzz',
    ])
  })
})
