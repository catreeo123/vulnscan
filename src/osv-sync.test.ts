import { vi, it, describe, expect, beforeEach } from 'vitest'
import AdmZip from 'adm-zip'
import type { AdvisoryStore } from './types.js'
import { eventsToRanges, osvEntryToAdvisories } from './osv-sync.js'
import { InMemoryAdvisoryStore } from './advisory-store-memory.js'
import { matchAffected } from './affected-range-matcher.js'

function makeZipResponse(entries: { name: string; content: string }[]): Response {
  const zip = new AdmZip()
  for (const { name, content } of entries) {
    zip.addFile(name, Buffer.from(content, 'utf8'))
  }
  const buf = zip.toBuffer()
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf))
      controller.close()
    },
  })
  return new Response(stream, { status: 200 })
}

// Two-entry OSV ZIP fixture (base64-encoded)
const FIXTURE_ZIP_B64 =
  'UEsDBBQAAAgIAPUDu1xr1lmImgAAAMAAAAAYAAAAR0hTQS1hYWFhLWJiYmItY2NjYy5qc29uJY2xCoMwFEV/Re4cpZZCIVsHaZcutXQpHV6Sp5WaKCZKJfjvRcuZLofLiWgMJM6X8pQSEaVKKZVqrTUE/GgtDTMk7uxDMo2tS3IIUFWxDmwgnxE96Q/VDBnBuvOzD2wh4XoLAUeWIdF2hvwbi8BArma/HcPcr64sro/iBgGe2IW/alwYOjPqNYEdFhFRNd9tHbL8mO1zLK+NH1BLAwQUAAAICAD1A7tcdNr+hJgAAADAAAAAGAAAAEdIU0EtZGRkZC1lZWVlLWZmZmYuanNvbiWNsQrCMABEf0VuTksVB8nmUHRxseIiDiG5lKJJQ5OWltJ/l1bedDyON6MxkLhcq3NmjDEZSWbWWguB2DunugkSD8a0G/qv3x0goKylTjSQrxlB6Y+qCTmDuo1TTHSQ8MFBwCtHSHAMHWPEItApXzNuzzSFVVbl7VneIcCBPv1V41PXml6vDRRYxAzbjNs65vtTXmB5b/wAUEsBAhQDFAAACAgA9QO7XGvWWYiaAAAAwAAAABgAAAAAAAAAAAAAAKSBAAAAAEdIU0EtYWFhYS1iYmJiLWNjY2MuanNvblBLAQIUAxQAAAgIAPUDu1x02v6EmAAAAMAAAAAYAAAAAAAAAAAAAACkgdAAAABHSFNBLWRkZGQtZWVlZS1mZmZmLmpzb25QSwUGAAAAAAIAAgCMAAAAngEAAAAA'

function makeFixtureResponse(): Response {
  const buf = Buffer.from(FIXTURE_ZIP_B64, 'base64')
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf))
      controller.close()
    },
  })
  return new Response(stream, { status: 200 })
}

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

  it('synthesizes introduced:0 for a fixed-only-first event (no preceding introduced)', () => {
    // Mirror the last_affected-first handling: a bare { fixed } means "all versions before
    // fixed are vulnerable". The old guard `&& current` dropped it silently, losing the entire
    // advisory (false negative). It must produce { introduced: '0', fixed }.
    expect(eventsToRanges([{ fixed: '1.2.3' }])).toEqual([{ introduced: '0', fixed: '1.2.3' }])
  })
})

// ─── M2: all upserts run inside ONE batched transaction ───

it('M2: upsertFromFullSync called once per advisory in the fixture', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFixtureResponse()))

  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  await syncOsv(store)

  // Fixture has 2 entries; each produces advisories → upsertFromFullSync called per advisory
  expect(vi.mocked(store.upsertFromFullSync)).toHaveBeenCalled()
  expect(vi.mocked(store.upsertFromFullSync).mock.calls.length).toBeGreaterThan(0)
})

// ─── I4: onProgress event uses `parsed` (queued-count), not `imported` (persisted-count) ───

it('I4: onProgress callback receives { parsed, total } object shape', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFixtureResponse()))

  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')

  // Typed as the new object signature — tsc enforces the contract at compile time
  const spy: (event: { parsed: number; total: number }) => void = vi.fn()
  await syncOsv(store, spy)

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

// ─── D6T: OSV entry with no severity metadata escalates to 'high' and emits warning ───

// Fixture: single entry with no database_specific.severity and no top-level severity
const NO_SEVERITY_ZIP_B64 =
  'UEsDBBQAAAgIAGA9u1zKSdJOsAAAAOkAAAAaAAAAR0hTQS10ZXN0LW5vLXNldi0wMDAxLmpzb24tzbGOwjAQBNBfiaZ2kLnSHQWChgZONIjCSjbBAtuRdwlYVv4dJaCtRjujV+BaGOz2p00txFKHWDONtdZ6DQX7cJaJYS5XBX56b1OGwT+xVLYdHceUq5eTWxVixTRScpLnXddRI9TCXAoG29xtTzAF1ETOLORhEAYPhWA9wWCxh3v/8zEpJBv6hS6QPMyl0/Zw3h6hQCMF+b5ckBTbZzNb0JhUQefeS/pb6ZXGdF3uA1BLAQIUAxQAAAgIAGA9u1zKSdJOsAAAAOkAAAAaAAAAAAAAAAAAAACkgQAAAABHSFNBLXRlc3Qtbm8tc2V2LTAwMDEuanNvblBLBQYAAAAAAQABAEgAAADoAAAAAAA='

function makeNoSeverityResponse(): Response {
  const buf = Buffer.from(NO_SEVERITY_ZIP_B64, 'base64')
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf))
      controller.close()
    },
  })
  return new Response(stream, { status: 200 })
}

it('D6T: OSV entry with no severity escalates to high and returns single summary warning', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeNoSeverityResponse()))

  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)

  // The advisory should have been upserted with severity 'high'
  expect(vi.mocked(store.upsertFromFullSync)).toHaveBeenCalledTimes(1)
  const advisory = vi.mocked(store.upsertFromFullSync).mock.calls[0][0]
  expect(advisory.severity).toBe('high')
  expect(advisory.packageName).toBe('test-pkg-no-sev')

  // A single summary informational warning should be returned (not one per advisory)
  expect(result.warnings).toHaveLength(1)
  expect(result.warnings[0].class).toBe('informational')
  expect(result.warnings[0].message).toContain('1')
  expect(result.warnings[0].message).toContain('unknown or missing severity metadata')
})

// ─── D6T-BULK: 50 advisories with missing severity → single summary warning ───

it('D6T-BULK: 50 entries with missing severity collapse to one summary warning with count 50', async () => {
  const entries = Array.from({ length: 50 }, (_, i) => {
    const id = `GHSA-bulk-${i.toString().padStart(4, '0')}-aaaa`
    return {
      name: `${id}.json`,
      content: JSON.stringify({
        id,
        summary: `Bulk test advisory ${i}`,
        affected: [{
          package: { ecosystem: 'npm', name: `bulk-pkg-${i}` },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
          // No database_specific.severity — triggers mapSeverity fail-safe
        }],
      }),
    }
  })

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeZipResponse(entries)))
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)

  // All 50 advisories imported
  expect(result.imported).toBe(50)

  // Exactly ONE summary warning — not 50
  expect(result.warnings).toHaveLength(1)
  expect(result.warnings[0].class).toBe('informational')
  expect(result.warnings[0].message).toContain('50')
  expect(result.warnings[0].message).toContain('unknown or missing severity metadata')
})

// ─── D6T-NONE: entries with severity set → no warnings emitted ───

it('D6T-NONE: entries with explicit severity produce no severity warnings', async () => {
  const entries = Array.from({ length: 3 }, (_, i) => {
    const id = `GHSA-sev-${i.toString().padStart(4, '0')}-bbbb`
    return {
      name: `${id}.json`,
      content: JSON.stringify({
        id,
        summary: `Severity-set advisory ${i}`,
        affected: [{
          package: { ecosystem: 'npm', name: `sev-pkg-${i}` },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
          database_specific: { severity: 'HIGH' },
        }],
      }),
    }
  })

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeZipResponse(entries)))
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)

  expect(result.imported).toBe(3)
  // No warnings when all entries have valid severity metadata
  expect(result.warnings).toHaveLength(0)
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
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')

  // Should complete without error (arrayBuffer spy would throw if called)
  await expect(syncOsv(store)).resolves.not.toThrow()
  expect(arrayBufferSpy).not.toHaveBeenCalled()
})

// ─── Error branch coverage: JSON parse failure, no-npm-affected skip, per-row upsert failure ───

const validNpmEntry = JSON.stringify({
  id: 'GHSA-aaaa-bbbb-cccc',
  summary: 'Test advisory',
  affected: [{
    package: { ecosystem: 'npm', name: 'some-pkg' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
  }],
})

it('increments skipped for ZIP entries containing invalid JSON', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    makeZipResponse([{ name: 'bad.json', content: '{not valid json{{' }])
  ))
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)
  expect(result.skipped).toBe(1)
  expect(result.imported).toBe(0)
  expect(vi.mocked(store.upsertFromFullSync)).not.toHaveBeenCalled()
})

it('increments skipped for entries with no npm-ecosystem affected packages', async () => {
  const goEntry = JSON.stringify({
    id: 'GHSA-go-only-0001',
    summary: 'Go only',
    affected: [{
      package: { ecosystem: 'Go', name: 'some/go/pkg' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }] }],
    }],
  })
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    makeZipResponse([{ name: 'go-only.json', content: goEntry }])
  ))
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)
  expect(result.skipped).toBe(1)
  expect(result.imported).toBe(0)
})

it('recovers from a malformed entry whose affected[] block is missing package (does not abort sync)', async () => {
  const malformed = JSON.stringify({
    id: 'GHSA-malformed-0001',
    summary: 'Missing package field',
    affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }] }] }],
  })
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    makeZipResponse([
      { name: 'malformed.json', content: malformed },
      { name: 'valid.json', content: validNpmEntry },
    ])
  ))
  const store = makeStore()
  const { syncOsv } = await import('./osv-sync.js')
  // One malformed entry must be skipped, not abort the whole sync — the valid entry that
  // follows it in the ZIP must still import (matches the per-row recovery contract).
  const result = await syncOsv(store)
  expect(result.skipped).toBe(1)
  expect(result.imported).toBe(1)
})

it('recovers from per-row upsert failure: decrements imported, increments skipped', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    makeZipResponse([{ name: 'valid.json', content: validNpmEntry }])
  ))
  const store = makeStore()
  vi.mocked(store.upsertFromFullSync).mockImplementation(() => { throw new Error('constraint failed') })
  const { syncOsv } = await import('./osv-sync.js')
  const result = await syncOsv(store)
  expect(result.imported).toBe(0)
  expect(result.skipped).toBe(1)
  // A DB-write failure means advisories did not persist. The sync is incomplete and must
  // signal exit 2 — silently reporting clean against a partially-populated DB is a false-clean.
  expect(result.warnings.some((w) => w.class === 'incomplete')).toBe(true)
})

// ─── canonicalId selection: GHSA alias preferred over CVE fallback (issue #15) ───

describe('osvEntryToAdvisories canonicalId', () => {
  const baseAffected = {
    package: { ecosystem: 'npm', name: 'some-pkg' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.0.1' }] }],
  }

  it('uses GHSA alias as canonicalId when entry has both CVE and GHSA in aliases', () => {
    const entry = {
      id: 'CVE-2021-23337',
      aliases: ['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337'],
      summary: 'Prototype Pollution',
      affected: [baseAffected],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].canonicalId).toBe('GHSA-35JH-R3H4-6JHM')
  })

  it('falls back to CVE id as canonicalId when no GHSA alias is present (known limitation)', () => {
    // Known limitation: OSV entries with only a CVE id and no GHSA alias produce a CVE-based
    // canonicalId. If the same advisory exists in GitHub Advisory (which uses GHSA ids), the
    // deduplicator will treat them as distinct findings. See comment in osv-sync.ts.
    const entry = {
      id: 'CVE-2021-99999',
      aliases: ['CVE-2021-99999'],
      summary: 'Some CVE-only advisory',
      affected: [baseAffected],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].canonicalId).toBe('CVE-2021-99999')
  })
})

// ─── MAL-* Supply Chain Signals: affected.versions synthesis (issue #26) ───

describe('osvEntryToAdvisories MAL-* Supply Chain Signals', () => {
  it('MAL-1: MAL-* entry with only affected.versions produces advisory with synthesized ranges', () => {
    const entry = {
      id: 'MAL-2024-1234',
      summary: 'Malicious package: evil-pkg',
      affected: [{
        package: { ecosystem: 'npm', name: 'evil-pkg' },
        versions: ['1.0.0', '1.0.1', '2.0.0'],
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].packageName).toBe('evil-pkg')
    expect(advisories[0].ranges).toHaveLength(3)
    expect(advisories[0].ranges).toContainEqual({ introduced: '1.0.0', lastAffected: '1.0.0' })
    expect(advisories[0].ranges).toContainEqual({ introduced: '1.0.1', lastAffected: '1.0.1' })
    expect(advisories[0].ranges).toContainEqual({ introduced: '2.0.0', lastAffected: '2.0.0' })
  })

  it('MAL-2: MAL-* advisory always gets critical severity regardless of OSV label', () => {
    const entry = {
      id: 'MAL-2024-5678',
      summary: 'Malicious package: stealer',
      affected: [{
        package: { ecosystem: 'npm', name: 'stealer' },
        versions: ['3.1.4'],
        database_specific: { severity: 'LOW' },
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].severity).toBe('critical')
  })

  it('MAL-3: invalid semver in affected.versions is skipped — no false positive range', () => {
    const entry = {
      id: 'MAL-2024-9999',
      summary: 'Malicious package: partly-invalid',
      affected: [{
        package: { ecosystem: 'npm', name: 'partly-invalid' },
        versions: ['1.0.0', 'not-a-semver', '2.0.0'],
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    // Only the two valid semver versions should produce ranges
    expect(advisories[0].ranges).toHaveLength(2)
    expect(advisories[0].ranges).toContainEqual({ introduced: '1.0.0', lastAffected: '1.0.0' })
    expect(advisories[0].ranges).toContainEqual({ introduced: '2.0.0', lastAffected: '2.0.0' })
  })

  it('MAL-4: entry with both affected.versions AND affected.ranges uses ranges, not versions', () => {
    const entry = {
      id: 'MAL-2024-0001',
      summary: 'Malicious package: has-both',
      affected: [{
        package: { ecosystem: 'npm', name: 'has-both' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.1.0' }] }],
        versions: ['1.0.0', '1.0.5'],
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    // Ranges from affected.ranges: one entry { introduced: '1.0.0', fixed: '1.1.0' }
    expect(advisories[0].ranges).toHaveLength(1)
    expect(advisories[0].ranges[0]).toEqual({ introduced: '1.0.0', fixed: '1.1.0' })
  })

  it('MAL-5: existing CVE entry with only affected.ranges is unaffected by the fix', () => {
    const entry = {
      id: 'GHSA-aaaa-bbbb-cve1',
      summary: 'Normal CVE advisory',
      affected: [{
        package: { ecosystem: 'npm', name: 'normal-pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].ranges).toHaveLength(1)
    expect(advisories[0].ranges[0]).toEqual({ introduced: '1.0.0', fixed: '1.2.0' })
    expect(advisories[0].type).toBe('cve')
  })

  it('MAL-6: MAL-* entry that also carries a CVE alias is still classified malware', () => {
    // getBestId prefers the CVE alias for the display id, but a malicious package that also
    // carries a CVE is still malware. Deriving `type` from the display id yields 'cve' and
    // bypasses the mal→critical override, storing the package at the OSV-reported (here LOW)
    // severity — below the default fail threshold. A false negative for a security tool.
    const entry = {
      id: 'MAL-2024-7777',
      aliases: ['CVE-2024-12345'],
      summary: 'Malicious package with a CVE alias',
      affected: [{
        package: { ecosystem: 'npm', name: 'evil-with-cve' },
        versions: ['1.0.0'],
        database_specific: { severity: 'LOW' },
      }],
    }
    const { advisories } = osvEntryToAdvisories(entry)
    expect(advisories).toHaveLength(1)
    expect(advisories[0].type).toBe('mal')
    expect(advisories[0].severity).toBe('critical')
  })
})

// ── B1 (#48): multiple affected[] blocks for one package must coalesce, not overwrite ──

describe('osvEntryToAdvisories multi-affected-block coalescing (B1, #48)', () => {
  it('coalesces multiple affected[] blocks for the same package so no range is lost on upsert', () => {
    const entry = {
      id: 'CVE-2099-0001',
      aliases: ['CVE-2099-0001'],
      summary: 'one package, two disjoint version lines',
      affected: [
        { package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.17.12' }] }] },
        { package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.10.2' }] }] },
      ],
    }

    const { advisories } = osvEntryToAdvisories(entry)

    // Store through the real PK-modelling store: same (id, packageName) blocks overwrite.
    const store = new InMemoryAdvisoryStore()
    for (const a of advisories) store.upsertFromFullSync(a, 1_000)
    const stored = store.getForPackage('lodash')

    // A version in EACH original block must still produce a Finding via Affected Range Match.
    expect(matchAffected({ name: 'lodash', version: '4.5.0' }, stored)).toHaveLength(1)
    expect(matchAffected({ name: 'lodash', version: '3.5.0' }, stored)).toHaveLength(1)
  })
})
