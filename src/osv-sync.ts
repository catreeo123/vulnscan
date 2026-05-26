import AdmZip from 'adm-zip'
import { pipeline } from 'node:stream/promises'
import { Readable } from 'node:stream'
import { createWriteStream, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Advisory, AdvisoryStore, SemverRange, Severity } from './types.js'

const OSV_NPM_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip'

type OsvEvent = { introduced?: string; fixed?: string; last_affected?: string }
type OsvRange = { type: string; events: OsvEvent[] }
type OsvAffected = {
  package: { ecosystem: string; name: string }
  ranges?: OsvRange[]
  database_specific?: { severity?: string }
}
type OsvEntry = {
  id: string
  aliases?: string[]
  summary?: string
  affected?: OsvAffected[]
  severity?: Array<{ type: string; score: string }>
  database_specific?: { severity?: string }
}

export async function syncOsv(
  store: AdvisoryStore,
  // "parsed" = queued in memory; store write happens in a single batch after the parse loop
  onProgress?: (event: { parsed: number; total: number }) => void,
): Promise<{ imported: number; skipped: number; fullSyncStartedAt: number }> {
  const fullSyncStartedAt = Date.now()
  process.stderr.write('OSV: downloading npm dump...\n')
  const res = await fetch(OSV_NPM_URL)
  if (!res.ok) throw new Error(`OSV download failed: ${res.status} ${res.statusText}`)
  if (!res.body) throw new Error('OSV download failed: response body is empty')

  let tmpDir: string | undefined
  try {
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-osv-'))
    const tmpZip = join(tmpDir, 'all.zip')
    await pipeline(Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]), createWriteStream(tmpZip))

    process.stderr.write(`OSV: extracting ZIP...\n`)
    const zip = new AdmZip(tmpZip)
    const entries = zip.getEntries()

    let imported = 0
    let skipped = 0
    const total = entries.length

    const allAdvisories: Advisory[] = []

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]
      if (!entry.entryName.endsWith('.json')) continue

      let parsed: OsvEntry
      try {
        parsed = JSON.parse(entry.getData().toString('utf8')) as OsvEntry
      } catch {
        skipped++
        continue
      }

      const advisories = osvEntryToAdvisories(parsed)
      if (advisories.length === 0) {
        skipped++
        continue
      }

      for (const advisory of advisories) {
        allAdvisories.push(advisory)
        imported++
      }
      if (onProgress && imported % 500 === 0) onProgress({ parsed: imported, total })
    }

    for (const a of allAdvisories) {
      try {
        store.upsertFromFullSync(a, fullSyncStartedAt)
      } catch (err) {
        // Per-row recovery: a single bad advisory must not abort the entire sync.
        skipped++
        imported--
        process.stderr.write(`Warning: skipping advisory ${a.id}: ${(err as Error).message}\n`)
      }
    }

    store.setLastSyncedAt('osv', Date.now())
    process.stderr.write(`OSV: imported ${imported} advisories (${skipped} skipped)\n`)
    return { imported, skipped, fullSyncStartedAt }
  } finally {
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
  }
}

function osvEntryToAdvisories(entry: OsvEntry): Advisory[] {
  const allAffected = entry.affected?.filter(
    (a) => a.package.ecosystem === 'npm' && a.package.name,
  ) ?? []

  if (allAffected.length === 0) return []

  const id = getBestId(entry)
  const type: 'cve' | 'mal' = id.startsWith('MAL-') ? 'mal' : 'cve'

  return allAffected.flatMap((affected): Advisory[] => {
    const semverRanges = (affected.ranges ?? [])
      .filter((r) => r.type === 'SEMVER')
      .flatMap((r) => eventsToRanges(r.events))

    if (semverRanges.length === 0) return []

    const url = `https://osv.dev/vulnerability/${entry.id}`
    const ghsaMatch = entry.id.match(/^GHSA-/i) ? entry.id : entry.aliases?.find((a) => a.match(/^GHSA-/i))
    const canonicalId = ghsaMatch ? ghsaMatch.toUpperCase() : id
    return [{
      id,
      canonicalId,
      type,
      packageName: affected.package.name,
      ranges: semverRanges,
      severity: mapSeverity(affected.database_specific?.severity ?? entry.database_specific?.severity),
      title: entry.summary ?? id,
      url,
    }]
  })
}

function getBestId(entry: OsvEntry): string {
  const cve = entry.aliases?.find((a) => a.startsWith('CVE-'))
  if (cve) return cve
  const mal = entry.id.startsWith('MAL-') ? entry.id : entry.aliases?.find((a) => a.startsWith('MAL-'))
  if (mal) return mal
  return entry.id
}

export function eventsToRanges(events: OsvEvent[]): SemverRange[] {
  const ranges: SemverRange[] = []
  let current: SemverRange | null = null

  for (const event of events) {
    if (event.introduced !== undefined) {
      if (current) ranges.push(current)
      current = { introduced: event.introduced }
    } else if (event.fixed !== undefined && current) {
      current.fixed = event.fixed
      ranges.push(current)
      current = null
    } else if (event.last_affected !== undefined) {
      if (current === null) current = { introduced: '0' }
      current.lastAffected = event.last_affected
      ranges.push(current)
      current = null
    }
  }

  if (current) ranges.push(current)
  return ranges
}

function mapSeverity(s: string | undefined): Severity {
  const u = s?.toUpperCase() ?? ''
  if (u === 'CRITICAL') return 'critical'
  if (u === 'HIGH') return 'high'
  if (u === 'MODERATE' || u === 'MEDIUM') return 'moderate'
  return 'low'
}
