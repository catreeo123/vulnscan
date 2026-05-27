import { vi, it, describe, expect, beforeEach } from 'vitest'
import type { AdvisoryStore } from './types.js'

vi.mock('./osv-sync.js', () => ({
  syncOsv: vi.fn().mockResolvedValue({ imported: 0, skipped: 0, fullSyncStartedAt: 1_000_000_000_000 }),
}))
vi.mock('./github-advisory-sync.js', () => ({
  syncGithubAdvisories: vi.fn().mockResolvedValue({ imported: 0, skipped: 0 }),
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
