import type { Advisory, AdvisoryStore, SemverRange } from './types.js'
import { incomplete } from './warnings.js'
import type { ScanWarning } from './warnings.js'
import { resolveAdvisorySeverity } from './severity-mapper.js'
import { assembleAdvisories, type PackageContribution } from './advisory-assembler.js'

const GITHUB_API = 'https://api.github.com'
const PER_PAGE = 100
const MAX_PAGES = 1000

export type SyncGithubOptions = {
  maxPages?: number
}

type GhVuln = {
  package: { ecosystem: string; name: string }
  vulnerable_version_range: string | null
  first_patched_version: string | null
}

type GhAdvisory = {
  ghsa_id: string
  cve_id: string | null
  severity: string
  html_url: string
  summary: string
  vulnerabilities: GhVuln[]
}

export async function syncGithubAdvisories(
  store: AdvisoryStore,
  since?: number,
  onProgress?: (imported: number) => void,
  options?: SyncGithubOptions,
): Promise<{ imported: number; skipped: number; warnings: ScanWarning[] }> {
  const maxPages = options?.maxPages ?? MAX_PAGES
  const token = process.env.GITHUB_TOKEN
  if (!token) {
    process.stderr.write('GitHub Advisory: no GITHUB_TOKEN — syncing at 60 req/hr (slow)\n')
  }

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  }
  if (token) headers.Authorization = `Bearer ${token}`

  let imported = 0
  let skipped = 0
  const warnings: ScanWarning[] = []
  let hitPageLimit = false

  process.stderr.write('GitHub Advisory: paginating npm advisories...\n')

  const sinceFilter =
    since !== undefined && Number.isFinite(since)
      ? `&updated=${encodeURIComponent('>=')}${new Date(since).toISOString().replace(/\.\d{3}Z$/, 'Z')}`
      : ''

  const passes: Array<{ type: 'reviewed' | 'malware'; advisoryType: Advisory['type'] }> = [
    { type: 'reviewed', advisoryType: 'cve' },
    { type: 'malware', advisoryType: 'mal' },
  ]

  for (const pass of passes) {
    let page = 0
    let passImported = 0
    let nextUrl: string | null =
      `${GITHUB_API}/advisories?type=${pass.type}&ecosystem=npm&per_page=${PER_PAGE}${sinceFilter}`

    while (nextUrl) {
      page++
      if (page > maxPages) {
        process.stderr.write(`\nGitHub Advisory: reached page limit (${maxPages}), stopping\n`)
        warnings.push(incomplete(`GitHub Advisory sync reached page limit (${maxPages}); results may be incomplete`))
        hitPageLimit = true
        break
      }

      const res = await fetchWithRetry(nextUrl, headers)
      const items = (await res.json()) as GhAdvisory[]

      if (!Array.isArray(items) || items.length === 0) break

      for (const item of items) {
        const { advisories, warnings: itemWarnings } = ghAdvisoryToAdvisories(item, pass.advisoryType)
        for (const advisory of advisories) {
          store.upsert(advisory)
          imported++
          passImported++
        }
        warnings.push(...itemWarnings)
        if (advisories.length === 0) skipped++
      }

      process.stderr.write(
        `GitHub Advisory: page ${page} (${pass.type}) — ${passImported} imported (${imported} total)\r`,
      )
      if (onProgress) onProgress(imported)

      nextUrl = parseLinkNext(res.headers.get('link'))
    }
  }

  // Only bump the cursor on clean exit of both passes. A mid-pagination throw
  // preserves the cursor so the next sync retries from the same point.
  // Also skip advancing when page limit was hit so the next run retries.
  if (!hitPageLimit) {
    store.setLastSyncedAt('github', Date.now())
  }
  process.stderr.write(`GitHub Advisory: imported ${imported} advisories (${skipped} items skipped)\n`)
  return { imported, skipped, warnings }
}

function parseLinkNext(link: string | null): string | null {
  if (!link) return null
  const match = link.match(/<([^>]+)>;\s*rel="next"/)
  return match ? match[1] : null
}

function ghAdvisoryToAdvisories(
  item: GhAdvisory,
  advisoryType: Advisory['type'],
): { advisories: Advisory[]; warnings: ScanWarning[] } {
  // Null-safe: GitHub's schema permits `vulnerabilities: null` and individual entries with a
  // null `package`. Mirrors the OSV path's `a?.package?.ecosystem` guard — an unguarded access
  // throws, aborting the whole pass and freezing the cursor (a permanent sync stall).
  const npmVulns = (item.vulnerabilities ?? []).filter((v) => v?.package?.ecosystem === 'npm')
  if (npmVulns.length === 0) return { advisories: [], warnings: [] }

  const id = item.cve_id ?? item.ghsa_id
  // Malware advisories are forced to critical here (shared with OSV) so a malware
  // package the GitHub feed under-rates is never stored below the fail threshold.
  const { severity, warning } = resolveAdvisorySeverity(advisoryType, item.severity, id)
  const itemWarnings: ScanWarning[] = warning ? [warning] : []

  const ghsaMatch = item.html_url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)
  const canonicalId = ghsaMatch ? ghsaMatch[0].toUpperCase() : item.ghsa_id.toUpperCase()

  // GitHub returns a separate vulnerabilities[] entry per disjoint range of a package;
  // all entries for the same package share PK (id, packageName), so the shared
  // advisory-assembler unions their ranges into ONE Advisory — otherwise the last-write-
  // wins upsert drops every range but the last (silent false negative).
  const contributions: PackageContribution[] = []
  for (const v of npmVulns) {
    if (!v.package.name || !v.vulnerable_version_range) continue
    contributions.push({
      packageName: v.package.name,
      ranges: parseGhRange(v.vulnerable_version_range),
      severity,
    })
  }

  const advisories = assembleAdvisories(
    { id, canonicalId, type: advisoryType, title: item.summary, url: item.html_url },
    contributions,
  )

  return { advisories, warnings: itemWarnings }
}

function parseGhRange(rangeStr: string): SemverRange[] {
  // GitHub Advisory range strings are valid semver range expressions.
  // Store as rawRange so AffectedRangeMatcher can use them directly.
  return [{ rawRange: rangeStr }]
}

export async function fetchWithRetry(
  url: string,
  headers: Record<string, string>,
  retries = 3,
): Promise<Response> {
  let finalStatus = 0
  let finalStatusText = ''
  for (let attempt = 0; attempt < retries; attempt++) {
    const res = await fetch(url, { headers })
    if (res.status === 429 || res.status === 403) {
      finalStatus = res.status
      finalStatusText = res.statusText
      const retryAfter = parseInt(res.headers.get('retry-after') ?? '60', 10)
      if (attempt < retries - 1) {
        process.stderr.write(`GitHub Advisory: rate limited, waiting ${retryAfter}s...\n`)
        await res.body?.cancel()
        await new Promise((r) => setTimeout(r, retryAfter * 1000))
        continue
      }
      await res.body?.cancel()
      break
    }
    if (!res.ok) throw new Error(`GitHub API error: ${res.status} ${res.statusText}`)
    return res
  }
  if (finalStatus === 403) {
    throw new Error(`GitHub API error: 403 ${finalStatusText} — check GITHUB_TOKEN`)
  }
  throw new Error('GitHub API: max retries exceeded')
}
