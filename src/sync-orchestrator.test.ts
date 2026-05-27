import { vi, it, describe, expect, beforeEach } from 'vitest'
import type { AdvisoryStore } from './types.js'

vi.mock('./osv-sync.js', () => ({
  syncOsv: vi.fn().mockResolvedValue({ imported: 0, skipped: 0, fullSyncStartedAt: 1_000_000_000_000, warnings: [] }),
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
    // Calls: 1=osv initial, 2=github initial, 3=osv double-check, 4=github double-check, 5+=since lookup
    let callCount = 0
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockImplementation(() => {
        callCount++
        if (callCount === 1) return Date.now() - 1000 // osv: fresh
        return future // github initial, double-checks, since lookup: all future
      }),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store, 24 * 60 * 60 * 1000)

    expect(warnings.some((w) => w.class === 'informational' && w.message.includes('clock skew'))).toBe(true)
  })
})

// ─── D9: syncGithubSafe emits incomplete warning on error ────────────────────

describe('D9: syncGithubSafe error → incomplete warning', () => {
  it('returns incomplete warning when syncGithubAdvisories throws', async () => {
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncGithubAdvisories).mockRejectedValueOnce(new Error('403 Forbidden'))

    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store)

    expect(warnings.some((w) => w.class === 'incomplete')).toBe(true)
    expect(warnings.some((w) => w.message.includes('403 Forbidden'))).toBe(true)
  })

  it('scrubs secrets from the error message in the incomplete warning', async () => {
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncGithubAdvisories).mockRejectedValueOnce(
      new Error('403 Forbidden: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456'),
    )

    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store)

    const incompleteWarning = warnings.find((w) => w.class === 'incomplete')
    expect(incompleteWarning).toBeDefined()
    expect(incompleteWarning!.message).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz123456')
    expect(incompleteWarning!.message).toContain('[REDACTED]')
  })
})

// ─── D5T: double-checked staleness ───────────────────────────────────────────

describe('D5T: double-checked staleness', () => {
  it('skips sync when a peer has refreshed cursors between initial check and double-check', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncOsv).mockClear()
    vi.mocked(syncGithubAdvisories).mockClear()

    // Initial check sees both stale (null), double-check sees both fresh (now)
    let callCount = 0
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockImplementation(() => {
        callCount++
        if (callCount <= 2) return null          // initial staleness decision: stale
        return Date.now()                        // double-check: peer already updated
      }),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    const result = await syncIfStale(store)

    expect(result).toEqual([])
    expect(vi.mocked(syncOsv)).not.toHaveBeenCalled()
    expect(vi.mocked(syncGithubAdvisories)).not.toHaveBeenCalled()
  })

  it('still syncs when double-check confirms stale (cursors stay null)', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    vi.mocked(syncOsv).mockClear()

    // Both initial and double-check return null
    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    await syncIfStale(store)

    expect(vi.mocked(syncOsv)).toHaveBeenCalledTimes(1)
  })
})

// ─── D8: clock-skew warning emitted even when double-check short-circuits ───

describe('D8: clock-skew warning survives double-check short-circuit', () => {
  it('emits clock-skew warning when osv skew detected but parallel process already synced', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncOsv).mockClear()
    vi.mocked(syncGithubAdvisories).mockClear()

    const future = Date.now() + 10 * 60 * 60 * 1000 // 10h in the future (triggers osvSkew=true)
    const fresh = Date.now() - 60_000               // 1 min ago (double-check sees fresh)

    // Calls in syncIfStale: 1=osv-init, 2=gh-init, 3=osv-double-check, 4=gh-double-check
    // osv-init returns future → osvSkew=true, osvStale=true
    // gh-init returns fresh → ghSkew=false, ghStale=false
    // osv-double-check returns fresh → osvStillStale=false
    // → double-check short-circuit fires; no sync should run
    let callCount = 0
    const store = makeStore({
      getLastSyncedAt: vi.fn().mockImplementation(() => {
        callCount++
        if (callCount === 1) return future // osv initial: skew detected
        return fresh                        // gh initial + all double-checks: fresh
      }),
    })

    const { syncIfStale } = await import('./sync-orchestrator.js')
    const warnings = await syncIfStale(store)

    // No sync should have been triggered (parallel process already refreshed)
    expect(vi.mocked(syncOsv)).not.toHaveBeenCalled()
    expect(vi.mocked(syncGithubAdvisories)).not.toHaveBeenCalled()
    // Clock-skew warning must still be emitted
    expect(warnings.some((w) => w.class === 'informational' && w.message.includes('clock skew'))).toBe(true)
  })
})
