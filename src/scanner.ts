import type { Finding, AdvisoryStore } from './types.js'
import type { Config } from './config.js'
import type { ScanWarning } from './warnings.js'
import { informational } from './warnings.js'
import { parseLockfile } from './lockfile-parser.js'
import { matchAffected } from './affected-range-matcher.js'
import { deduplicate } from './deduplicator.js'
import { syncIfStale } from './sync-orchestrator.js'

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
  const osvLast = store.getLastSyncedAt('osv')
  const ghLast = store.getLastSyncedAt('github')
  const warnings: ScanWarning[] = []
  if (osvLast === null || now - osvLast > SEVEN_DAYS_MS) {
    warnings.push(
      informational(
        `Advisory database may be stale: OSV data ${osvLast === null ? 'has never been synced' : `was last synced ${Math.floor((now - osvLast) / (24 * 60 * 60 * 1000))} day(s) ago`}. Run \`vulnscan update\` to refresh.`,
      ),
    )
  }
  if (ghLast === null || now - ghLast > SEVEN_DAYS_MS) {
    warnings.push(
      informational(
        `Advisory database may be stale: GitHub Advisory data ${ghLast === null ? 'has never been synced' : `was last synced ${Math.floor((now - ghLast) / (24 * 60 * 60 * 1000))} day(s) ago`}. Run \`vulnscan update\` to refresh.`,
      ),
    )
  }
  return warnings
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  const { lockfileContent, packageJsonContent, store, config, noSync } = input
  const doSync = input.sync ?? syncIfStale

  const { deps, warnings: parseWarnings } = parseLockfile(lockfileContent, packageJsonContent)

  const extraWarnings: ScanWarning[] = []
  if (noSync) {
    extraWarnings.push(...offlineStalenessWarnings(store))
  } else {
    const syncWarnings = await doSync(store, config.stalenessMs)
    extraWarnings.push(...syncWarnings)
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
    warnings.push(...offlineStalenessWarnings(store))
  } else {
    const syncWarnings = await doSync(store, config.stalenessMs)
    warnings.push(...syncWarnings)
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
