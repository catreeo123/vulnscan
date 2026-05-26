import semver from 'semver'
import type { Dep, Advisory, Finding, SemverRange } from './types.js'

export function normalizeRawRange(raw: string): string {
  return raw.replace(/,\s*/g, ' ')
}

function buildSemverRange(range: SemverRange): string {
  const lower = `>=${range.introduced ?? '0'}`
  if (range.fixed) return `${lower} <${range.fixed}`
  if (range.lastAffected) return `${lower} <=${range.lastAffected}`
  return lower
}

export function matchAffected(dep: Dep, advisories: Advisory[]): Finding[] {
  const findings: Finding[] = []

  for (const advisory of advisories) {
    if (advisory.packageName !== dep.name) continue

    const matched = advisory.ranges.some((range) => {
      const raw = range.rawRange ? normalizeRawRange(range.rawRange) : undefined
      const semverRange = raw
        ?? buildSemverRange(range)
      return semver.satisfies(dep.version, semverRange, { includePrerelease: true })
    })

    if (matched) {
      findings.push({ name: dep.name, version: dep.version, via: dep.via, advisory })
    }
  }

  return findings
}
