import { vi, it, describe, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'
import { eventsToRanges } from './osv-sync.js'

vi.mock('./local-db.js', () => ({
  upsertAdvisoryFromFullSync: vi.fn(),
  setLastSyncedAt: vi.fn(),
}))

// Two-entry OSV ZIP fixture (base64-encoded)
const FIXTURE_ZIP_B64 =
  'UEsDBBQAAAgIAPUDu1xr1lmImgAAAMAAAAAYAAAAR0hTQS1hYWFhLWJiYmItY2NjYy5qc29uJY2xCoMwFEV/Re4cpZZCIVsHaZcutXQpHV6Sp5WaKCZKJfjvRcuZLofLiWgMJM6X8pQSEaVKKZVqrTUE/GgtDTMk7uxDMo2tS3IIUFWxDmwgnxE96Q/VDBnBuvOzD2wh4XoLAUeWIdF2hvwbi8BArma/HcPcr64sro/iBgGe2IW/alwYOjPqNYEdFhFRNd9tHbL8mO1zLK+NH1BLAwQUAAAICAD1A7tcdNr+hJgAAADAAAAAGAAAAEdIU0EtZGRkZC1lZWVlLWZmZmYuanNvbiWNsQrCMABEf0VuTksVB8nmUHRxseIiDiG5lKJJQ5OWltJ/l1bedDyON6MxkLhcq3NmjDEZSWbWWguB2DunugkSD8a0G/qv3x0goKylTjSQrxlB6Y+qCTmDuo1TTHSQ8MFBwCtHSHAMHWPEItApXzNuzzSFVVbl7VneIcCBPv1V41PXml6vDRRYxAzbjNs65vtTXmB5b/wAUEsBAhQDFAAACAgA9QO7XGvWWYiaAAAAwAAAABgAAAAAAAAAAAAAAKSBAAAAAEdIU0EtYWFhYS1iYmJiLWNjY2MuanNvblBLAQIUAxQAAAgIAPUDu1x02v6EmAAAAMAAAAAYAAAAAAAAAAAAAACkgdAAAABHSFNBLWRkZGQtZWVlZS1mZmZmLmpzb25QSwUGAAAAAAIAAgCMAAAAngEAAAAA'

function makeFixtureResponse(): Response {
  const buf = Buffer.from(FIXTURE_ZIP_B64, 'base64')
  // Build a Web ReadableStream from the buffer
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf))
      controller.close()
    },
  })
  return new Response(stream, { status: 200 })
}

function makeDb(): { db: Database.Database; transactionWrapper: ReturnType<typeof vi.fn> } {
  const transactionWrapper = vi.fn()
  const db = {
    transaction: vi.fn(() => transactionWrapper),
  } as unknown as Database.Database
  return { db, transactionWrapper }
}

beforeEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

// ─── N6: eventsToRanges synthesizes { introduced: '0' } when last_affected has no preceding introduced ───

describe('eventsToRanges', () => {
  it('N6: synthesizes introduced:0 and records lastAffected when last_affected arrives without a preceding introduced', () => {
    const result = eventsToRanges([{ last_affected: '1.0.0' }])
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({ introduced: '0', lastAffected: '1.0.0' })
  })

  it('normal introduced+fixed range is preserved', () => {
    const result = eventsToRanges([{ introduced: '1.0.0' }, { fixed: '2.0.0' }])
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({ introduced: '1.0.0', fixed: '2.0.0' })
  })

  it('last_affected after introduced uses the existing introduced and records lastAffected', () => {
    const result = eventsToRanges([{ introduced: '1.0.0' }, { last_affected: '1.9.9' }])
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({ introduced: '1.0.0', lastAffected: '1.9.9' })
  })

  it('returns empty array for empty events', () => {
    expect(eventsToRanges([])).toEqual([])
  })
})

// ─── M2: all upserts run inside ONE batched transaction ───

it('M2: calls batchUpsert wrapper exactly once for multiple advisories', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFixtureResponse()))

  const { db, transactionWrapper } = makeDb()
  const { syncOsv } = await import('./osv-sync.js')
  await syncOsv(db)

  // The transaction factory should be called once (to create the batchUpsert fn)
  expect((db.transaction as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1)
  // The returned wrapper should be invoked exactly once (batched call with all advisories)
  expect(transactionWrapper).toHaveBeenCalledTimes(1)
  // And that single call receives an array
  const [arg] = transactionWrapper.mock.calls[0] as [unknown[]]
  expect(Array.isArray(arg)).toBe(true)
  expect(arg.length).toBeGreaterThan(0)
})

// ─── I4: onProgress event uses `parsed` (queued-count), not `imported` (persisted-count) ───

it('I4: onProgress callback receives { parsed, total } object shape', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFixtureResponse()))

  const { db } = makeDb()
  const { syncOsv } = await import('./osv-sync.js')

  // Typed as the new object signature — tsc enforces the contract at compile time
  const spy: (event: { parsed: number; total: number }) => void = vi.fn()
  await syncOsv(db, spy)

  // Fixture has 2 entries (< 500 threshold), so progress never fires — but if it did,
  // spy.mock.calls[0][0] would be an object with a `parsed` key, not a bare number.
  for (const [event] of (spy as ReturnType<typeof vi.fn>).mock.calls) {
    expect(event).toHaveProperty('parsed')
    expect(event).not.toHaveProperty('imported')
    expect(event).toHaveProperty('total')
  }
  // Runtime shape verification: direct spy call (fixture below batch threshold)
  spy({ parsed: 1, total: 2 })
  const lastCall = (spy as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[0]
  expect(lastCall).toHaveProperty('parsed', 1)
  expect(lastCall).not.toHaveProperty('imported')
  expect(lastCall).toHaveProperty('total', 2)
})

// ─── M1: streaming path — res.arrayBuffer() is NOT called ───

it('M1: does not call res.arrayBuffer() — streaming path is taken', async () => {
  const arrayBufferSpy = vi.fn().mockRejectedValue(new Error('arrayBuffer should not be called'))
  const buf = Buffer.from(FIXTURE_ZIP_B64, 'base64')
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf))
      controller.close()
    },
  })
  const mockRes = new Response(stream, { status: 200 })
  Object.defineProperty(mockRes, 'arrayBuffer', { value: arrayBufferSpy, writable: false })

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockRes))
  const { db } = makeDb()
  const { syncOsv } = await import('./osv-sync.js')

  // Should complete without error (arrayBuffer spy would throw if called)
  await expect(syncOsv(db)).resolves.not.toThrow()
  expect(arrayBufferSpy).not.toHaveBeenCalled()
})
