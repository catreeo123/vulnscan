import type { Finding, Severity } from './types.js'
import type { Config } from './config.js'
import { validateFailOn } from './config.js'
import type { ScanWarning } from './warnings.js'
import { hasIncomplete } from './warnings.js'

/** Severity floor ordering; a higher index is a more severe rating. */
const SEVERITY_ORDER: Severity[] = ['low', 'moderate', 'high', 'critical']

/**
 * Resolve the effective fail-on severity set. An explicit `--fail-on` CSV (validated,
 * never blindly cast) overrides config; otherwise the already-loaded config's `failOn`
 * is used.
 *
 * Takes the already-loaded `Config` rather than a project directory, so the caller's
 * single `loadConfig()` is reused — the previous `getFailOn(arg, dir)` re-read
 * `.vulnscanrc` a second time per scan/check.
 */
export function resolveFailOn(failOnArg: string | null, config: Config): Severity[] {
  if (failOnArg) return validateFailOn(failOnArg.split(','))
  return config.failOn
}

function shouldFail(findings: Finding[], failOn: Severity[]): boolean {
  const indices = failOn.map((s) => SEVERITY_ORDER.indexOf(s)).filter((i) => i >= 0)
  if (indices.length === 0) return false
  const threshold = Math.min(...indices)
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.advisory.severity) >= threshold)
}

/**
 * Exit code matrix (priority: incomplete > findings > clean):
 *   2 — at least one incomplete warning (scan may have missed packages; findings are untrustworthy)
 *   1 — no incomplete warnings, but at least one finding is at or above the failOn floor
 *   0 — clean (no qualifying findings AND no incomplete warnings)
 *
 * Exit 2 takes priority over exit 1 because an incomplete scan cannot be trusted:
 * the missing packages may have had worse findings than the ones reported.
 */
export function computeExitCode(findings: Finding[], warnings: ScanWarning[], failOn: Severity[]): number {
  if (hasIncomplete(warnings)) return 2
  if (shouldFail(findings, failOn)) return 1
  return 0
}
