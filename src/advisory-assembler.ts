import type { Advisory, SemverRange, Severity } from './types.js'
import { SEVERITY_ORDER } from './types.js'

/** Fields shared by every Advisory coalesced from a single upstream entry. */
export type AdvisoryIdentity = {
  id: string
  canonicalId: string
  type: Advisory['type']
  title: string
  url: string
}

/** One package's contribution to an advisory: its affected ranges + the severity for that block. */
export type PackageContribution = {
  packageName: string
  ranges: SemverRange[]
  severity: Severity
}

/**
 * Coalesce per-package contributions into one Advisory per (id, packageName).
 *
 * A single upstream entry (one OSV entry, or one GitHub advisory) can list the same
 * package across multiple affected blocks / disjoint ranges. Those all share the
 * primary key (id, packageName), so their ranges MUST be unioned into a single
 * Advisory — otherwise the last-write-wins upsert keeps only the final block and
 * silently drops the rest (false negative; OSV #48 / B1). Severity fails safe to the
 * most severe rating seen for that package across its contributions.
 *
 * Both Source adapters (osv-sync, github-advisory-sync) feed this seam, so the merge
 * invariant has exactly one home and one test surface.
 *
 * Contributions whose range list is empty are dropped — there is nothing for the
 * matcher to test, and an empty-range Advisory would never produce a Finding.
 */
export function assembleAdvisories(
  identity: AdvisoryIdentity,
  contributions: PackageContribution[],
): Advisory[] {
  const byPackage = new Map<string, { ranges: SemverRange[]; severity: Severity }>()

  for (const c of contributions) {
    if (c.ranges.length === 0) continue
    const existing = byPackage.get(c.packageName)
    if (existing) {
      existing.ranges.push(...c.ranges)
      // Fail-safe: keep the most severe rating seen across blocks for the same package.
      if (SEVERITY_ORDER.indexOf(c.severity) > SEVERITY_ORDER.indexOf(existing.severity)) existing.severity = c.severity
    } else {
      byPackage.set(c.packageName, { ranges: [...c.ranges], severity: c.severity })
    }
  }

  return [...byPackage].map(([packageName, { ranges, severity }]) => ({
    ...identity,
    packageName,
    ranges,
    severity,
  }))
}
