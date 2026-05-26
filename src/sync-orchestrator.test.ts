import { vi, it, expect, beforeEach } from 'vitest'
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
