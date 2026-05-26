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

    if (!existing || SEVERITY_RANK[finding.advisory.severity] > SEVERITY_RANK[existing.advisory.severity]) {
      map.set(key, finding)
    }
  }

  return Array.from(map.values())
}
