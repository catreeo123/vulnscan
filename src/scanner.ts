import type { Finding, AdvisoryStore } from './types.js'
import type { Config } from './config.js'
import type { ScanWarning } from './warnings.js'
import { parseLockfile } from './lockfile-parser.js'
import { matchAffected } from './affected-range-matcher.js'
import { deduplicate } from './deduplicator.js'
import { syncIfStale } from './sync-orchestrator.js'

export type CheckInput = {
  name: string
  version: string
  store: AdvisoryStore
  config: Config
}

export type CheckResult = {
  findings: Finding[]
  advisoryCount: number
}

export type ScanInput = {
  lockfileContent: string
  packageJsonContent?: string
  store: AdvisoryStore
  config: Config
}

export type ScanResult = {
  findings: Finding[]
  warnings: ScanWarning[]
  advisoryCount: number
  depCount: number
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  const { lockfileContent, packageJsonContent, store, config } = input

  const { deps, warnings } = parseLockfile(lockfileContent, packageJsonContent)

  await syncIfStale(store, config.stalenessHours * 60 * 60 * 1000)

  const allFindings: Finding[] = []
  for (const dep of deps) {
    const advisories = store.getForPackage(dep.name)
    if (advisories.length === 0) continue
    const findings = matchAffected(dep, advisories)
    allFindings.push(...findings)
  }

  const deduped = deduplicate(allFindings)
  const count = store.count()

  return {
    findings: deduped,
    warnings,
    advisoryCount: count,
    depCount: deps.length,
  }
}

export async function checkPackage(input: CheckInput): Promise<CheckResult> {
  const { name, version, store, config } = input

  await syncIfStale(store, config.stalenessHours * 60 * 60 * 1000)

  const advisories = store.getForPackage(name)
  const findings = deduplicate(matchAffected({ name, version }, advisories))
  const count = store.count()

  return {
    findings,
    advisoryCount: count,
  }
}
