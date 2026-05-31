import semver from 'semver'
import type { Dep, Advisory, Finding, SemverRange } from '../core/types.js'

export function normalizeRawRange(raw: string): string {
  return raw.replace(/,\s*/g, ' ')
}

function buildSemverRange(range: SemverRange): string {
  // `|| '0'`, not `?? '0'`: an empty-string introduced (allowed by SemverRange, and OSV treats
  // "" as equivalent to "0") is not null/undefined, so `??` would let it through and produce
  // ">=" — an invalid range that semver.satisfies() silently rejects as false (false negative).
  const lower = `>=${range.introduced || '0'}`
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
