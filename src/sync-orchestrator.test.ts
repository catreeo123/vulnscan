import { vi, it, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'

vi.mock('./local-db.js', () => ({
  getLastSyncedAt: vi.fn(),
  setLastSyncedAt: vi.fn(),
  pruneStaleAdvisories: vi.fn().mockReturnValue(0),
}))
vi.mock('./osv-sync.js', () => ({
  syncOsv: vi.fn().mockResolvedValue({ imported: 0, skipped: 0, fullSyncStartedAt: 1_000_000_000_000 }),
}))
vi.mock('./github-advisory-sync.js', () => ({
  syncGithubAdvisories: vi.fn().mockResolvedValue({ imported: 0, skipped: 0 }),
}))

function makeDb(): Database.Database {
  return {} as unknown as Database.Database
}

beforeEach(() => {
  vi.resetModules()
})

it('DB error in getLastSyncedAt for since-lookup propagates out of syncIfStale', async () => {
  const { getLastSyncedAt } = await import('./local-db.js')
  vi.mocked(getLastSyncedAt)
    .mockReturnValueOnce(null)  // osv staleness → stale
    .mockReturnValueOnce(null)  // github staleness → stale
    .mockImplementationOnce(() => { throw new Error('db locked') }) // since lookup in syncGithubSafe

  const { syncIfStale } = await import('./sync-orchestrator.js')
  await expect(syncIfStale(makeDb())).rejects.toThrow('db locked')
})
