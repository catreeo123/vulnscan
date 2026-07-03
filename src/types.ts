export type Dep = { name: string; version: string; via?: string; local?: boolean }

export type Severity = 'critical' | 'high' | 'moderate' | 'low'

/** Canonical low→critical ordering; a higher index is a more severe rating. Single source of
 * truth for both the fail-on threshold comparison (failure-threshold.ts) and the "most severe
 * wins" advisory merge (advisory-assembler.ts) — they must never drift independently. */
export const SEVERITY_ORDER: Severity[] = ['low', 'moderate', 'high', 'critical']

export type SemverRange = {
  introduced?: string
  fixed?: string
  lastAffected?: string
  rawRange?: string
}

export type Advisory = {
  id: string
  canonicalId: string
  type: 'cve' | 'mal'
  packageName: string
  ranges: SemverRange[]
  severity: Severity
  title: string
  url: string
}

export type Finding = {
  name: string
  version: string
  via?: string
  advisory: Advisory
}

export type AdvisoryStore = {
  getForPackage(name: string): Advisory[]
  upsert(advisory: Advisory): void
  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void
  count(): number
  pruneStale(fullSyncStartedAt: number, gracePeriodMs: number): void
  getLastSyncedAt(source: string): number | null
  setLastSyncedAt(source: string, ts: number): void
  close(): void
}
