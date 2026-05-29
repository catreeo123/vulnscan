import { vi, it, expect, describe, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs'
import * as zlib from 'node:zlib'
import * as streamPromises from 'node:stream/promises'

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return { ...actual, existsSync: vi.fn(), mkdirSync: vi.fn(), createWriteStream: vi.fn(), renameSync: vi.fn(), rmSync: vi.fn() }
})

vi.mock('node:zlib', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:zlib')>()
  return { ...actual, createGunzip: vi.fn() }
})

vi.mock('node:stream/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:stream/promises')>()
  return { ...actual, pipeline: vi.fn() }
})

vi.mock('./local-db.js', () => ({ DB_PATH: '/tmp/test-vulnscan.sqlite' }))
vi.mock('./secrets.js', () => ({ scrubSecrets: (msg: string) => msg }))

const { bootstrapDb, maybeBootstrap } = await import('./bootstrap.js')

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let stderrSpy: any

beforeEach(() => {
  vi.resetAllMocks()
  delete process.env.VULNSCAN_NO_BOOTSTRAP
  global.fetch = vi.fn()
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
})

afterEach(() => {
  stderrSpy.mockRestore()
  delete process.env.VULNSCAN_NO_BOOTSTRAP
})

describe('maybeBootstrap', () => {
  it('does nothing if DB file already exists', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(true)

    await maybeBootstrap()

    expect(global.fetch).not.toHaveBeenCalled()
    expect(stderrSpy).not.toHaveBeenCalled()
  })

  it('calls bootstrapDb if DB file does not exist', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false)
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ assets: [] }),
    })

    await maybeBootstrap()

    expect(stderrSpy).toHaveBeenCalledWith('Bootstrapping advisory database from latest release…\n')
  })
})

describe('bootstrapDb', () => {
  it('returns false immediately if VULNSCAN_NO_BOOTSTRAP is set', async () => {
    process.env.VULNSCAN_NO_BOOTSTRAP = '1'

    const result = await bootstrapDb()

    expect(result).toBe(false)
    expect(global.fetch).not.toHaveBeenCalled()
    expect(stderrSpy).not.toHaveBeenCalled()
  })

  it('returns false and warns if GitHub API has no matching asset', async () => {
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ assets: [] }),
    })

    const result = await bootstrapDb()

    expect(result).toBe(false)
    expect(stderrSpy).toHaveBeenCalledWith('Bootstrapping advisory database from latest release…\n')
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('no db.sqlite.gz asset'))
  })

  it('returns false and warns if asset download returns non-OK status', async () => {
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          assets: [{ name: 'db.sqlite.gz', browser_download_url: 'https://example.com/db.sqlite.gz' }],
        }),
      })
      .mockResolvedValueOnce({ ok: false, status: 404, body: null })

    const result = await bootstrapDb()

    expect(result).toBe(false)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('HTTP 404'))
  })

  it('downloads, decompresses, and writes DB file on success', async () => {
    const mockBody = new ReadableStream()
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          assets: [{ name: 'db.sqlite.gz', browser_download_url: 'https://example.com/db.sqlite.gz' }],
        }),
      })
      .mockResolvedValueOnce({ ok: true, body: mockBody })

    const mockGunzip = {}
    const mockWriteStream = {}
    vi.mocked(zlib.createGunzip).mockReturnValue(mockGunzip as any)
    vi.mocked(fs.createWriteStream).mockReturnValue(mockWriteStream as any)
    vi.mocked(streamPromises.pipeline).mockResolvedValue(undefined)

    const result = await bootstrapDb()

    expect(result).toBe(true)
    expect(fs.mkdirSync).toHaveBeenCalledWith(expect.any(String), { recursive: true })
    expect(streamPromises.pipeline).toHaveBeenCalledWith(expect.anything(), mockGunzip, mockWriteStream)
    // Atomic publish: download lands on a temp path, then renames onto the live DB.
    expect(fs.renameSync).toHaveBeenCalledWith(
      expect.stringContaining('/tmp/test-vulnscan.sqlite'),
      '/tmp/test-vulnscan.sqlite',
    )
    const [tmpArg, finalArg] = vi.mocked(fs.renameSync).mock.calls[0]
    expect(tmpArg).not.toBe(finalArg)
    expect(stderrSpy).toHaveBeenCalledWith('Bootstrapping advisory database from latest release…\n')
    expect(stderrSpy).toHaveBeenCalledWith('Bootstrap complete.\n')
  })

  it('cleans up the temp file and does not rename when the download stream fails', async () => {
    const mockBody = new ReadableStream()
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          assets: [{ name: 'db.sqlite.gz', browser_download_url: 'https://example.com/db.sqlite.gz' }],
        }),
      })
      .mockResolvedValueOnce({ ok: true, body: mockBody })

    vi.mocked(zlib.createGunzip).mockReturnValue({} as any)
    vi.mocked(fs.createWriteStream).mockReturnValue({} as any)
    vi.mocked(streamPromises.pipeline).mockRejectedValue(new Error('connection reset mid-stream'))

    const result = await bootstrapDb()

    expect(result).toBe(false)
    // The partial download must be removed, and the live DB must never be replaced.
    expect(fs.rmSync).toHaveBeenCalledWith(expect.stringContaining('/tmp/test-vulnscan.sqlite'), expect.anything())
    expect(fs.renameSync).not.toHaveBeenCalled()
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('connection reset mid-stream'))
  })

  it('returns false and warns if fetch throws', async () => {
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('network error'))

    const result = await bootstrapDb()

    expect(result).toBe(false)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('network error'))
  })

  it('fetches releases from the db-latest tag URL', async () => {
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ assets: [] }),
    })

    await bootstrapDb()

    const fetchCall = vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(fetchCall[0]).toContain('db-latest')
  })

  it('returns false and logs fallback message when no asset found', async () => {
    vi.mocked(global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ assets: [] }),
    })

    const result = await bootstrapDb()

    expect(result).toBe(false)
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('falling back to full sync'),
    )
  })
})
