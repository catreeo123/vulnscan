import type { Finding, Severity } from './types.js'

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
}

export function deduplicate(findings: Finding[]): Finding[] {
  const map = new Map<string, Finding>()

  for (const finding of findings) {
    const key = `${finding.name}@${finding.version}:${finding.advisory.canonicalId}`
    const existing = map.get(key)

    if (!existing) {
      map.set(key, finding)
      continue
    }

    const finRank = SEVERITY_RANK[finding.advisory.severity]
    const exRank = SEVERITY_RANK[existing.advisory.severity]
    // Higher severity wins. On a severity tie, a malware Finding wins over a non-malware one so the
    // type='mal' signal (and its "remove, don't upgrade" remediation) is never dropped just because
    // a CVE row happened to sort/arrive first — getForPackage orders canonical_id, id ASC, so a CVE
    // id precedes a MAL-/GHSA id sharing the same canonicalId.
    const tieFavorsMal =
      finRank === exRank && finding.advisory.type === 'mal' && existing.advisory.type !== 'mal'

    if (finRank > exRank || tieFavorsMal) {
      map.set(key, finding)
    }
  }

  return Array.from(map.values())
}
