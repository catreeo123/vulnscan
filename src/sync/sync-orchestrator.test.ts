import { vi, it, describe, expect, beforeEach } from 'vitest'
import type { AdvisoryStore } from '../core/types.js'

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

// ─── OSV sync failure degrades gracefully (parity with syncGithubSafe) ───────

describe('OSV sync failure → incomplete warning (no crash)', () => {
  it('syncIfStale: syncOsv rejection yields an incomplete warning, does not throw, and does not advance the OSV cursor or prune', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    vi.mocked(syncOsv).mockRejectedValueOnce(new Error('OSV download failed: 503 Service Unavailable'))
    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')

    const warnings = await syncIfStale(store)

    expect(warnings.some((w) => w.class === 'incomplete')).toBe(true)
    // Cannot prune or advance the cursor on a failed full Sync — would drop live Advisories.
    expect(vi.mocked(store.pruneStale)).not.toHaveBeenCalled()
    expect(vi.mocked(store.setLastSyncedAt)).not.toHaveBeenCalledWith('osv', expect.any(Number))
  })

  it('syncIfStale: scrubs secrets from the OSV failure warning', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    vi.mocked(syncOsv).mockRejectedValueOnce(new Error('failed with token=ghp_abcdefghijklmnopqrstuvwxyz123456'))
    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')

    const warnings = await syncIfStale(store)
    const inc = warnings.find((w) => w.class === 'incomplete')
    expect(inc).toBeDefined()
    expect(inc!.message).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz123456')
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

// ─── D10: runSync surfaces page-limit warnings to stderr ─────────────────────

describe('D10: runSync surfaces page-limit warnings to stderr', () => {
  it('writes incomplete warning to stderr when syncGithubAdvisories returns one', async () => {
    // Import both modules from the same fresh registry so they share the mock instance.
    // (vi.resetModules in beforeEach clears the registry before each test.)
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    const { runSync } = await import('./sync-orchestrator.js')

    vi.mocked(syncGithubAdvisories).mockResolvedValueOnce({
      imported: 0,
      skipped: 0,
      warnings: [{ class: 'incomplete', message: 'GitHub Advisory sync reached page limit (2); results may be incomplete' }],
    })

    const written: string[] = []
    const origWrite = process.stderr.write.bind(process.stderr)
    ;(process.stderr as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    const store = makeStore()
    await runSync(store)
    ;(process.stderr as any).write = origWrite

    expect(written.join('')).toMatch(/page limit/)
  })

  it('runSync returns the incomplete warning so the update command can fail safe', async () => {
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    const { runSync } = await import('./sync-orchestrator.js')

    vi.mocked(syncGithubAdvisories).mockResolvedValueOnce({
      imported: 0,
      skipped: 0,
      warnings: [{ class: 'incomplete', message: 'GitHub Advisory sync reached page limit (2); results may be incomplete' }],
    })

    const written: string[] = []
    const origWrite = process.stderr.write.bind(process.stderr)
    ;(process.stderr as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    const store = makeStore()
    const warnings = await runSync(store)
    ;(process.stderr as any).write = origWrite

    expect(warnings.some((w) => w.class === 'incomplete')).toBe(true)
  })
})

// ─── runSync: OSV failure degrades to incomplete (exit 2), not a throw (exit 1) ──

describe('runSync: OSV sync failure degrades to an incomplete warning', () => {
  it('returns an incomplete warning (does not throw) and does not prune/advance the OSV cursor when syncOsv rejects', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    const { runSync } = await import('./sync-orchestrator.js')
    vi.mocked(syncOsv).mockRejectedValueOnce(new Error('OSV download failed: 503 Service Unavailable'))

    const origWrite = process.stderr.write.bind(process.stderr)
    ;(process.stderr as any).write = () => true
    const store = makeStore()
    // A throw here would propagate to the CLI's top-level catch → exit 1 ("findings"); an OSV
    // sync failure during `vulnscan update` is an incomplete sync and must map to exit 2.
    const warnings = await runSync(store)
    ;(process.stderr as any).write = origWrite

    expect(warnings.some((w) => w.class === 'incomplete')).toBe(true)
    // A failed full pull must not prune (would delete live advisories against partial data) or
    // advance the OSV cursor (would mask the failed sync as a fresh successful one).
    expect(vi.mocked(store.pruneStale)).not.toHaveBeenCalled()
    expect(vi.mocked(store.setLastSyncedAt)).not.toHaveBeenCalledWith('osv', expect.any(Number))
  })
})

// ─── #24: push(...big) RangeError regression tests ───────────────────────────

describe('#24: loop-push — huge OSV warning array does not overflow stack', () => {
  it('syncIfStale resolves when syncOsv returns 200k warnings (no RangeError)', async () => {
    const { syncOsv } = await import('./osv-sync.js')
    vi.mocked(syncOsv).mockResolvedValueOnce({
      imported: 0,
      skipped: 0,
      fullSyncStartedAt: 1_000_000_000_000,
      warnings: Array.from({ length: 200_000 }, () => ({ class: 'informational' as const, message: 'x' })),
    })

    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    await expect(syncIfStale(store)).resolves.not.toThrow()
  })
})

describe('#24: loop-push — huge GitHub warning array does not overflow stack', () => {
  it('syncIfStale resolves when syncGithubAdvisories returns 200k warnings (no RangeError)', async () => {
    const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
    vi.mocked(syncGithubAdvisories).mockResolvedValueOnce({
      imported: 0,
      skipped: 0,
      warnings: Array.from({ length: 200_000 }, () => ({ class: 'informational' as const, message: 'x' })),
    })

    const store = makeStore()
    const { syncIfStale } = await import('./sync-orchestrator.js')
    await expect(syncIfStale(store)).resolves.not.toThrow()
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
