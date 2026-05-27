import { vi, it, expect, beforeEach, describe } from 'vitest'
import type { AdvisoryStore } from './types.js'

function makeStore(): AdvisoryStore {
  return {
    getForPackage: vi.fn().mockReturnValue([]),
    upsert: vi.fn(),
    upsertFromFullSync: vi.fn(),
    count: vi.fn().mockReturnValue(0),
    pruneStale: vi.fn(),
    getLastSyncedAt: vi.fn().mockReturnValue(null),
    setLastSyncedAt: vi.fn(),
    close: vi.fn(),
  }
}

function makeEmptyFetch(): ReturnType<typeof vi.fn> {
  return vi.fn().mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

beforeEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

it('omits updated filter when since is undefined', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(makeStore(), undefined)

  const url = mockFetch.mock.calls[0][0] as string
  expect(url).not.toContain('updated=')
})

it('includes URL-encoded >= updated filter when since is provided', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const since = new Date('2024-06-01').getTime()

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(makeStore(), since)

  const url = mockFetch.mock.calls[0][0] as string
  expect(url).toContain('updated=%3E%3D2024-06-01T')
})

it('omits updated filter when since is non-finite (NaN or Infinity)', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(makeStore(), NaN)

  const url = mockFetch.mock.calls[0][0] as string
  expect(url).not.toContain('updated=')
})

it('calls setLastSyncedAt when since provided, even if 0 items imported', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const since = new Date('2024-06-01').getTime()
  const store = makeStore()

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(store, since)

  expect(vi.mocked(store.setLastSyncedAt)).toHaveBeenCalled()
})

it('bumps setLastSyncedAt even when incremental sync returns zero advisories', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const since = 12345
  const store = makeStore()

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(store, since)

  expect(vi.mocked(store.setLastSyncedAt)).toHaveBeenCalled()
  const calledWith = vi.mocked(store.setLastSyncedAt).mock.calls[0]
  expect(calledWith[0]).toBe('github')
  expect(calledWith[1]).toBeGreaterThan(since)
})

describe('fetchWithRetry', () => {
  it('does not sleep on the final retry attempt (M6)', async () => {
    const rateLimitedResponse = () =>
      new Response(null, {
        status: 429,
        headers: { 'retry-after': '1' },
      })

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(rateLimitedResponse()))

    const { fetchWithRetry } = await import('./github-advisory-sync.js')

    const start = performance.now()
    await expect(fetchWithRetry('https://example.com', {}, 3)).rejects.toThrow(
      'GitHub API: max retries exceeded',
    )
    const elapsed = performance.now() - start

    // With retries=3: should sleep (retries-1)=2 times × 1000ms = ~2000ms.
    // Without the fix it sleeps 3 times = ~3000ms.
    expect(elapsed).toBeLessThan(2200)
  })

  it('cancels response body on every retry attempt (M06)', async () => {
    const cancelFn = vi.fn().mockResolvedValue(undefined)
    const rateLimitedResponse = () =>
      ({
        status: 429,
        statusText: 'Too Many Requests',
        headers: new Headers({ 'retry-after': '0' }),
        body: { cancel: cancelFn },
      }) as unknown as Response

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(rateLimitedResponse()))

    const { fetchWithRetry } = await import('./github-advisory-sync.js')

    await expect(fetchWithRetry('https://example.com', {}, 3)).rejects.toThrow()
    expect(cancelFn).toHaveBeenCalledTimes(3)
  })

  it('throws error containing 403 when every attempt returns 403', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(null, { status: 403, statusText: 'Forbidden' })),
    )

    const { fetchWithRetry } = await import('./github-advisory-sync.js')
    await expect(fetchWithRetry('https://example.com', {}, 1)).rejects.toThrow(/403/)
  })
})

it('preserves last-synced cursor when fetch throws mid-pagination', async () => {
  const validItem = {
    ghsa_id: 'GHSA-1234-5678-abcd',
    cve_id: null,
    severity: 'high',
    html_url: 'https://github.com/advisories/GHSA-1234-5678-abcd',
    summary: 'Test advisory',
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: 'test-pkg' },
        vulnerable_version_range: '< 1.0.0',
        first_patched_version: '1.0.0',
      },
    ],
  }

  const mockFetch = vi.fn()
    .mockResolvedValueOnce(
      new Response(JSON.stringify([validItem]), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          link: '<https://api.github.com/advisories?page=2>; rel="next"',
        },
      }),
    )
    .mockRejectedValueOnce(new Error('network error on page 2'))

  vi.stubGlobal('fetch', mockFetch)

  const store = makeStore()
  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await expect(syncGithubAdvisories(store, 12345)).rejects.toThrow('network error on page 2')

  expect(vi.mocked(store.setLastSyncedAt)).not.toHaveBeenCalled()
})

it('fetches both type=reviewed and type=malware URLs', async () => {
  const mockFetch = makeEmptyFetch()
  vi.stubGlobal('fetch', mockFetch)

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(makeStore(), undefined)

  const urls = mockFetch.mock.calls.map((c) => c[0] as string)
  expect(urls.some((u) => u.includes('type=reviewed'))).toBe(true)
  expect(urls.some((u) => u.includes('type=malware'))).toBe(true)
})

it('malware pass stores advisories with type=mal; reviewed pass stores type=cve', async () => {
  const makeItem = (ghsaId: string) => ({
    ghsa_id: ghsaId,
    cve_id: null,
    severity: 'high',
    html_url: `https://github.com/advisories/${ghsaId}`,
    summary: 'Test advisory',
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: 'test-pkg' },
        vulnerable_version_range: '< 1.0.0',
        first_patched_version: '1.0.0',
      },
    ],
  })

  const reviewedItem = makeItem('GHSA-aaaa-bbbb-cccc')
  const malwareItem = makeItem('GHSA-dddd-eeee-ffff')

  const mockFetch = vi
    .fn()
    // reviewed pass — single page, no next link
    .mockImplementationOnce(() =>
      Promise.resolve(
        new Response(JSON.stringify([reviewedItem]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )
    // malware pass — single page, no next link
    .mockImplementationOnce(() =>
      Promise.resolve(
        new Response(JSON.stringify([malwareItem]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )

  vi.stubGlobal('fetch', mockFetch)

  const store = makeStore()
  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  await syncGithubAdvisories(store, undefined)

  const upsertCalls = vi.mocked(store.upsert).mock.calls
  const types = upsertCalls.map((c) => c[0].type)
  expect(types).toContain('cve')
  expect(types).toContain('mal')
})

// ── D8: MAX_PAGES warning ────────────────────────────────────────────────────

it('returns incomplete warning when maxPages cap is reached', async () => {
  const makePagedFetch = (pageCount: number) => {
    const mockFn = vi.fn()
    for (let i = 0; i < pageCount; i++) {
      const isLast = i === pageCount - 1
      mockFn.mockImplementationOnce(() =>
        Promise.resolve(
          new Response(JSON.stringify([{ ghsa_id: `GHSA-${i}-0000-0000`, cve_id: null, severity: 'high', html_url: `https://github.com/advisories/GHSA-${i}`, summary: 'test', vulnerabilities: [] }]), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...(isLast ? {} : { link: `<https://api.github.com/advisories?page=${i + 2}>; rel="next"` }),
            },
          }),
        ),
      )
    }
    return mockFn
  }

  // maxPages: 2, but there are 3 pages of results (reviewed pass triggers cap)
  const mockFetch = makePagedFetch(3)
  vi.stubGlobal('fetch', mockFetch)

  const { syncGithubAdvisories } = await import('./github-advisory-sync.js')
  const result = await syncGithubAdvisories(makeStore(), undefined, undefined, { maxPages: 2 })

  expect(result.warnings).toHaveLength(1)
  expect(result.warnings[0].class).toBe('incomplete')
  expect(result.warnings[0].message).toMatch(/page limit/)
})
