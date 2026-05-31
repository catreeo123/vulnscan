import { describe, it, expect } from 'vitest'
import { computeExitCode, resolveFailOn } from './failure-threshold.js'
import type { Finding } from './types.js'
import type { Config } from './config.js'
import { incomplete, informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

function finding(severity: 'critical' | 'high' | 'moderate' | 'low'): Finding {
  return {
    name: 'pkg', version: '1.0.0',
    advisory: {
      id: 'CVE-test', canonicalId: 'CVE-test', type: 'cve',
      packageName: 'pkg', ranges: [], severity, title: 'test', url: 'https://example.com',
    },
  }
}
const noWarnings: ScanWarning[] = []

function config(failOn: Config['failOn']): Config {
  return { failOn, stalenessHours: 24, stalenessMs: 24 * 60 * 60 * 1000 }
}

describe('computeExitCode — threshold semantics (#20)', () => {
  it('exits 1 when finding severity equals the failOn floor', () => {
    expect(computeExitCode([finding('low')], noWarnings, ['low'])).toBe(1)
  })

  it('exits 1 when finding severity is above the failOn floor', () => {
    expect(computeExitCode([finding('moderate')], noWarnings, ['low'])).toBe(1)
  })

  it('exits 0 when finding severity is below the failOn floor', () => {
    expect(computeExitCode([finding('low')], noWarnings, ['moderate'])).toBe(0)
  })

  it('exits 0 for moderate when failOn is high', () => {
    expect(computeExitCode([finding('moderate')], noWarnings, ['high'])).toBe(0)
  })

  it('exits 1 for critical when failOn is high', () => {
    expect(computeExitCode([finding('critical')], noWarnings, ['high'])).toBe(1)
  })

  it('uses lowest severity in failOn list as the floor', () => {
    // ['critical', 'high'] → floor is 'high'; moderate should not trigger
    expect(computeExitCode([finding('moderate')], noWarnings, ['critical', 'high'])).toBe(0)
  })

  // GAP #1: incomplete warning must beat exit 1 (priority: 2 > 1 > 0)
  it('exits 2 when qualifying finding AND incomplete warning present (2 beats 1)', () => {
    expect(computeExitCode([finding('critical')], [incomplete('git dep skipped')], ['critical'])).toBe(2)
  })

  it('exits 2 for incomplete even with no findings (data untrustworthy)', () => {
    expect(computeExitCode([], [incomplete('git dep skipped')], ['high'])).toBe(2)
  })

  it('exits 1 when only informational warning and qualifying finding (informational does not override)', () => {
    expect(computeExitCode([finding('high')], [informational('db slightly stale')], ['high'])).toBe(1)
  })

  // GAP #2: empty failOn — shouldFail short-circuits on empty indices
  it('exits 0 with empty failOn array even with critical findings', () => {
    expect(computeExitCode([finding('critical')], noWarnings, [])).toBe(0)
  })

  // GAP #6: moderate boundary (middle of SEVERITY_ORDER)
  it('exits 1 for moderate finding when failOn is moderate (at-threshold match)', () => {
    expect(computeExitCode([finding('moderate')], noWarnings, ['moderate'])).toBe(1)
  })

  it('exits 0 for low finding when failOn is moderate (below threshold)', () => {
    expect(computeExitCode([finding('low')], noWarnings, ['moderate'])).toBe(0)
  })

  it('exits 1 for critical finding when failOn is moderate (above threshold)', () => {
    expect(computeExitCode([finding('critical')], noWarnings, ['moderate'])).toBe(1)
  })
})

describe('resolveFailOn', () => {
  it('returns the config failOn when no --fail-on argument is given', () => {
    expect(resolveFailOn(null, config(['critical', 'high']))).toEqual(['critical', 'high'])
  })

  it('an explicit --fail-on CSV overrides config', () => {
    expect(resolveFailOn('low,moderate', config(['critical']))).toEqual(['low', 'moderate'])
  })

  it('validates the --fail-on CSV (invalid severities fall back to defaults, not blind cast)', () => {
    // validateFailOn rejects unknown severities and returns the defaults, never the raw strings.
    expect(resolveFailOn('bogus', config(['high']))).toEqual(['critical', 'high'])
  })
})
