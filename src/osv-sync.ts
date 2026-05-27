import AdmZip from 'adm-zip'
import { pipeline } from 'node:stream/promises'
import { Readable } from 'node:stream'
import { createWriteStream, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Advisory, AdvisoryStore, SemverRange } from './types.js'
import { mapSeverity } from './severity-mapper.js'
import { informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

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
): Promise<{ imported: number; skipped: number; fullSyncStartedAt: number; warnings: ScanWarning[] }> {
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
    let missingSeverityCount = 0

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

      const { advisories, warnings } = osvEntryToAdvisories(parsed)
      if (advisories.length === 0) {
        skipped++
        continue
      }

      for (const advisory of advisories) {
        allAdvisories.push(advisory)
        imported++
      }
      // Count per-entry severity warnings; don't accumulate all — avoids V8 spread overflow
      // when sync-orchestrator spreads this array for 100k+ advisories (issue #23).
      missingSeverityCount += warnings.filter((w) => w.class === 'informational').length
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

    process.stderr.write(`OSV: imported ${imported} advisories (${skipped} skipped)\n`)
    const warnings: ScanWarning[] = []
    if (missingSeverityCount > 0) {
      const noun = missingSeverityCount === 1 ? 'advisory has' : 'advisories have'
      warnings.push(
        informational(
          `${missingSeverityCount} ${noun} unknown or missing severity metadata; defaulted to 'high' (fail-safe escalation)`,
        ),
      )
    }
    return { imported, skipped, fullSyncStartedAt, warnings }
  } finally {
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
  }
}

export function osvEntryToAdvisories(entry: OsvEntry): { advisories: Advisory[]; warnings: ScanWarning[] } {
  const allAffected = entry.affected?.filter(
    (a) => a.package.ecosystem === 'npm' && a.package.name,
  ) ?? []

  if (allAffected.length === 0) return { advisories: [], warnings: [] }

  const id = getBestId(entry)
  const type: 'cve' | 'mal' = id.startsWith('MAL-') ? 'mal' : 'cve'

  const advisories: Advisory[] = []
  const warnings: ScanWarning[] = []

  for (const affected of allAffected) {
    const semverRanges = (affected.ranges ?? [])
      .filter((r) => r.type === 'SEMVER')
      .flatMap((r) => eventsToRanges(r.events))

    if (semverRanges.length === 0) continue

    const url = `https://osv.dev/vulnerability/${entry.id}`
    const ghsaMatch = entry.id.match(/^GHSA-/i) ? entry.id : entry.aliases?.find((a) => a.match(/^GHSA-/i))
    // GHSA ids are the stable cross-source identifier; prefer them when present in entry.id or aliases.
    // Known limitation: OSV entries with no GHSA alias (e.g. CVE-only entries not mirrored to GitHub
    // Advisory) will use the CVE id as canonicalId. If the same advisory exists in GitHub Advisory,
    // it will carry a GHSA canonicalId, causing the deduplicator to treat them as distinct findings.
    // A cross-reference lookup would fix this but is out of scope — the advisory databases eventually
    // converge and GHSA entries in OSV carry the GHSA alias, so in practice this gap is rare.
    const canonicalId = ghsaMatch ? ghsaMatch.toUpperCase() : id
    const { severity, warning } = mapSeverity({
      label: affected.database_specific?.severity ?? entry.database_specific?.severity,
      advisoryId: id,
    })
    if (warning) warnings.push(warning)
    advisories.push({
      id,
      canonicalId,
      type,
      packageName: affected.package.name,
      ranges: semverRanges,
      severity,
      title: entry.summary ?? id,
      url,
    })
  }

  return { advisories, warnings }
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

