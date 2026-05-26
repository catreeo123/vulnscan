import type { Finding } from './types.js'
import type { Config } from './config.js'
import type Database from 'better-sqlite3'
import { parseLockfile } from './lockfile-parser.js'
import { getAdvisoriesForPackage, advisoryCount } from './local-db.js'
import { matchAffected } from './affected-range-matcher.js'
import { deduplicate } from './deduplicator.js'
import { syncIfStale } from './sync-orchestrator.js'

export type CheckInput = {
  name: string
  version: string
  db: Database.Database
  config: Config
}

export type CheckResult = {
  findings: Finding[]
  advisoryCount: number
}

export type ScanInput = {
  lockfileContent: string
  packageJsonContent?: string
  db: Database.Database
  config: Config
}

export type ScanResult = {
  findings: Finding[]
  warnings: string[]
  advisoryCount: number
  depCount: number
}

export async function runScan(input: ScanInput): Promise<ScanResult> {
  const { lockfileContent, packageJsonContent, db, config } = input

  const { deps, warnings } = parseLockfile(lockfileContent, packageJsonContent)

  await syncIfStale(db, config.stalenessHours * 60 * 60 * 1000)

  const allFindings: Finding[] = []
  for (const dep of deps) {
    const advisories = getAdvisoriesForPackage(db, dep.name)
    if (advisories.length === 0) continue
    const findings = matchAffected(dep, advisories)
    allFindings.push(...findings)
  }

  const deduped = deduplicate(allFindings)
  const count = advisoryCount(db)

  return {
    findings: deduped,
    warnings,
    advisoryCount: count,
    depCount: deps.length,
  }
}

export async function checkPackage(input: CheckInput): Promise<CheckResult> {
  const { name, version, db, config } = input

  await syncIfStale(db, config.stalenessHours * 60 * 60 * 1000)

  const advisories = getAdvisoriesForPackage(db, name)
  const findings = deduplicate(matchAffected({ name, version }, advisories))
  const count = advisoryCount(db)

  return {
    findings,
    advisoryCount: count,
  }
}
