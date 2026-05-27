import { vi, it, describe, expect, beforeEach } from 'vitest'
import type { AdvisoryStore } from './types.js'

vi.mock('./osv-sync.js', () => ({
  syncOsv: vi.fn().mockResolvedValue({ imported: 0, skipped: 0, fullSyncStartedAt: 1_000_000_000_000 }),
}))
vi.mock('./github-advisory-sync.js', () => ({
  syncGithubAdvisories: vi.fn().mockResolvedValue({ imported: 0, skipped: 0, warnings: [] }),
}))

function makeStore(overrides: Partial<AdvisoryStore> = {}): AdvisoryStore {
  return {
    getForPackage: vi.fn().mockReturnValue([]),
    upsert: vi.fn(),
    upsertFromFullSync: vi.fn(),
    count: vi.fn().mockReturnValue(0),
    pruneStale: vi.fn(),
    getLastSyncedAt: vi.fn().mockReturnValue(null),
    setLastSyncedAt: vi.fn(),
    close: vi.fn(),
    ...overrides,
  }
}

beforeEach(() => {
  vi.resetModules()
})

it('store error in getLastSyncedAt for since-lookup propagates out of syncIfStale', async () => {
  let callCount = 0
  const store = makeStore({
    getLastSyncedAt: vi.fn().mockImplementation(() => {
      callCount++
      if (callCount <= 2) return null
      throw new Error('db locked')
    }),
  })

  const { syncIfStale } = await import('./sync-orchestrator.js')
  await expect(syncIfStale(store)).rejects.toThrow('db locked')
})

// ─── D2: OSV cursor is written by orchestrator AFTER pruneStale, not inside syncOsv ───

describe('D2: OSV cursor-after-prune ordering', () => {
  it('syncIfStale: cursor is NOT updated when pruneStale throws', async () => {
    const store = makeStore({
      pruneStale: vi.fn().mockImplementation(() => {
        throw new Error('prune failed')
      }),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    await expect(syncIfStale(store)).rejects.toThrow('prune failed')
    expect(vi.mocked(store.setLastSyncedAt)).not.toHaveBeenCalledWith('osv', expect.any(Number))
  })

  it('syncIfStale: cursor IS updated with osv source after pruneStale succeeds', async () => {
    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    await syncIfStale(store)
    expect(vi.mocked(store.setLastSyncedAt)).toHaveBeenCalledWith('osv', expect.any(Number))
  })
})

// ─── D8: syncIfStale returns ScanWarning[] ───────────────────────────────────

describe('D8: syncIfStale warning propagation', () => {
  it('returns warnings from syncGithubAdvisories when github sync runs', async () => {
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncGithubAdvisories).mockResolvedValueOnce({
      imported: 0,
      skipped: 0,
      warnings: [{ class: 'incomplete', message: 'GitHub Advisory sync reached page limit (2); results may be incomplete' }],
    })

    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store)

    expect(warnings).toHaveLength(1)
    expect(warnings[0].class).toBe('incomplete')
    expect(warnings[0].message).toMatch(/page limit/)
  })

  it('returns empty warnings when no sync runs (fresh sources)', async () => {
    const now = Date.now()
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockReturnValue(now),
    })
    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store, 24 * 60 * 60 * 1000)

    expect(warnings).toEqual([])
  })
})

// ─── D8: clock-skew guard ────────────────────────────────────────────────────

describe('D8: clock-skew guard', () => {
  it('treats now < lastSyncedAt as stale and emits informational warning (OSV)', async () => {
    const future = Date.now() + 10 * 60 * 60 * 1000 // 10h in the future
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockReturnValue(future),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store, 24 * 60 * 60 * 1000)

    // Should have forced sync (called setLastSyncedAt for osv)
    expect(vi.mocked(store.setLastSyncedAt)).toHaveBeenCalledWith('osv', expect.any(Number))
    // Should emit clock-skew informational warning
    expect(warnings.some((w) => w.class === 'informational' && w.message.includes('clock skew'))).toBe(true)
  })

  it('treats now < lastSyncedAt as stale and emits informational warning (GitHub)', async () => {
    const future = Date.now() + 10 * 60 * 60 * 1000
    // OSV is fresh (past), GitHub is future
    let callCount = 0
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockImplementation(() => {
        callCount++
        if (callCount <= 2) {
          // First two calls: osv and github staleness check — osv is fresh, github is future
          return callCount === 1 ? Date.now() - 1000 : future
        }
        // Third call: since lookup in syncGithubSafe
        return future
      }),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store, 24 * 60 * 60 * 1000)

    expect(warnings.some((w) => w.class === 'informational' && w.message.includes('clock skew'))).toBe(true)
  })
})
