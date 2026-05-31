import type { Finding, AdvisoryStore } from '../core/types.js'
import type { Config } from '../core/config.js'
import type { ScanWarning } from '../core/warnings.js'
import { informational, incomplete } from '../core/warnings.js'
import { parseLockfile } from '../lockfile/lockfile-parser.js'
import { matchAffected } from '../match/affected-range-matcher.js'
import { deduplicate } from '../match/deduplicator.js'
import { syncIfStale } from '../sync/sync-orchestrator.js'

type SyncFn = (store: AdvisoryStore, stalenessMs: number) => Promise<ScanWarning[]>

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000

export type CheckInput = {
  name: string
  version: string
  store: AdvisoryStore
  config: Config
  noSync?: boolean
  sync?: SyncFn
}

export type CheckResult = {
  findings: Finding[]
  advisoryCount: number
  warnings: ScanWarning[]
}

export type ScanInput = {
  lockfileContent: string
  packageJsonContent?: string
  store: AdvisoryStore
  config: Config
  noSync?: boolean
  sync?: SyncFn
}

export type ScanResult = {
  findings: Finding[]
  warnings: ScanWarning[]
  advisoryCount: number
  depCount: number
}

function offlineStalenessWarnings(store: AdvisoryStore): ScanWarning[] {
  const now = Date.now()
  const warnings: ScanWarning[] = []
  // A source that has never been synced means zero coverage for it: an offline scan against
  // an empty database would otherwise report clean (exit 0) — a false-clean. That is
  // `incomplete` (exit 2). Present-but-aged data is only `informational`.
  const checkSource = (source: 'osv' | 'github', label: string): void => {
    const last = store.getLastSyncedAt(source)
    if (last === null) {
      warnings.push(
        incomplete(
          `Advisory database ${label} data has never been synced; results are unreliable (no coverage). Run \`vulnscan update\` to populate it.`,
        ),
      )
    } else if (now - last > SEVEN_DAYS_MS) {
      warnings.push(
        informational(
          `Advisory database may be stale: ${label} data was last synced ${Math.floor((now - last) / (24 * 60 * 60 * 1000))} day(s) ago. Run \`vulnscan update\` to refresh.`,
        ),
      )
    }
  }
  checkSource('osv', 'OSV')
  checkSource('github', 'GitHub Advisory')
  return warnings
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  const { lockfileContent, packageJsonContent, store, config, noSync } = input
  const doSync = input.sync ?? syncIfStale

  const { deps, warnings: parseWarnings } = parseLockfile(lockfileContent, packageJsonContent)

  const extraWarnings: ScanWarning[] = []
  if (noSync) {
    for (const w of offlineStalenessWarnings(store)) extraWarnings.push(w)
  } else {
    const syncWarnings = await doSync(store, config.stalenessMs)
    for (const w of syncWarnings) extraWarnings.push(w)
  }

  const allFindings: Finding[] = []
  for (const dep of deps) {
    if (dep.local) continue
    const advisories = store.getForPackage(dep.name)
    if (advisories.length === 0) continue
    const findings = matchAffected(dep, advisories)
    allFindings.push(...findings)
  }

  const deduped = deduplicate(allFindings)
  const count = store.count()

  return {
    findings: deduped,
    warnings: [...parseWarnings, ...extraWarnings],
    advisoryCount: count,
    depCount: deps.filter((d) => !d.local).length,
  }
}

export async function checkPackage(input: CheckInput): Promise<CheckResult> {
  const { name, version, store, config, noSync } = input
  const doSync = input.sync ?? syncIfStale

  const warnings: ScanWarning[] = []
  if (noSync) {
    for (const w of offlineStalenessWarnings(store)) warnings.push(w)
  } else {
    const syncWarnings = await doSync(store, config.stalenessMs)
    for (const w of syncWarnings) warnings.push(w)
  }

  const advisories = store.getForPackage(name)
  const findings = deduplicate(matchAffected({ name, version }, advisories))
  const count = store.count()

  return {
    findings,
    advisoryCount: count,
    warnings,
  }
}
