import { describe, it, expect } from 'vitest'
import { deduplicate } from './deduplicator.js'
import type { Finding } from './types.js'

const baseFinding = (overrides: Partial<Finding> = {}): Finding => ({
  name: 'lodash',
  version: '4.17.20',
  advisory: {
    id: 'CVE-2021-23337',
    canonicalId: 'CVE-2021-23337',
    type: 'cve',
    packageName: 'lodash',
    ranges: [{ introduced: '0', fixed: '4.17.21' }],
    severity: 'high',
    title: 'Prototype Pollution',
    url: 'https://example.com',
  },
  ...overrides,
})

describe('deduplicate', () => {
  it('returns empty array for empty input', () => {
    expect(deduplicate([])).toEqual([])
  })

  it('preserves two Findings for different CVEs on the same package', () => {
    const finding1 = baseFinding()
    const finding2 = baseFinding({
      advisory: { ...baseFinding().advisory, id: 'CVE-2020-8203', canonicalId: 'CVE-2020-8203', title: 'Other vuln' },
    })

    const result = deduplicate([finding1, finding2])

    expect(result).toHaveLength(2)
  })

  it('merges OSV and GitHub findings for same GHSA across different advisory IDs', () => {
    const osvFinding = baseFinding({
      advisory: {
        ...baseFinding().advisory,
        id: 'GHSA-8cp3-66vr-3r4c',
        canonicalId: 'GHSA-8CP3-66VR-3R4C',
        url: 'https://osv.dev/vulnerability/GHSA-8cp3-66vr-3r4c',
        severity: 'high',
      },
    })
    const ghFinding = baseFinding({
      advisory: {
        ...baseFinding().advisory,
        id: 'CVE-2022-29622',
        canonicalId: 'GHSA-8CP3-66VR-3R4C',
        url: 'https://github.com/advisories/GHSA-8cp3-66vr-3r4c',
        severity: 'critical',
      },
    })

    const result = deduplicate([osvFinding, ghFinding])

    expect(result).toHaveLength(1)
    expect(result[0].advisory.severity).toBe('critical')
  })

  it('merges two Findings for same CVE, keeping higher severity', () => {
    const osvFinding = baseFinding()
    const ghFinding = baseFinding({
      advisory: { ...baseFinding().advisory, severity: 'critical' },
    })

    const result = deduplicate([osvFinding, ghFinding])

    expect(result).toHaveLength(1)
    expect(result[0].advisory.severity).toBe('critical')
  })

  it('deduplicates CVE-only and GHSA-URL advisories for same vuln via canonicalId', () => {
    const cveFinding = baseFinding({
      advisory: {
        ...baseFinding().advisory,
        id: 'CVE-2026-1234',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234',
        canonicalId: 'GHSA-ABCD-EFGH-IJKL',
        severity: 'high',
      },
    })
    const ghsaFinding = baseFinding({
      advisory: {
        ...baseFinding().advisory,
        id: 'GHSA-abcd-efgh-ijkl',
        url: 'https://github.com/advisories/GHSA-abcd-efgh-ijkl',
        canonicalId: 'GHSA-ABCD-EFGH-IJKL',
        severity: 'high',
      },
    })

    const result = deduplicate([cveFinding, ghsaFinding])

    expect(result).toHaveLength(1)
  })

  it('keeps the malware Finding over a CVE on a critical-severity tie (cve arrives first)', () => {
    // getAdvisoriesForPackage orders canonical_id ASC, id ASC, so a CVE-id row sorts before a
    // MAL-/GHSA-id row sharing the same canonicalId → the cve Finding enters the map first. A
    // strict `>` severity comparison then drops the equally-critical malware Finding, losing the
    // type='mal' signal the skill contract keys on. Malware must win the tie.
    const cveFinding = baseFinding({
      advisory: { ...baseFinding().advisory, id: 'CVE-2099-1', canonicalId: 'GHSA-TIE-AAAA-BBBB', type: 'cve', severity: 'critical' },
    })
    const malFinding = baseFinding({
      advisory: { ...baseFinding().advisory, id: 'GHSA-tie-aaaa-bbbb', canonicalId: 'GHSA-TIE-AAAA-BBBB', type: 'mal', severity: 'critical' },
    })

    const result = deduplicate([cveFinding, malFinding])
    expect(result).toHaveLength(1)
    expect(result[0].advisory.type).toBe('mal')
  })

  it('keeps the malware Finding regardless of input order (mal arrives first)', () => {
    const cveFinding = baseFinding({
      advisory: { ...baseFinding().advisory, id: 'CVE-2099-1', canonicalId: 'GHSA-TIE-AAAA-BBBB', type: 'cve', severity: 'critical' },
    })
    const malFinding = baseFinding({
      advisory: { ...baseFinding().advisory, id: 'GHSA-tie-aaaa-bbbb', canonicalId: 'GHSA-TIE-AAAA-BBBB', type: 'mal', severity: 'critical' },
    })

    const result = deduplicate([malFinding, cveFinding])
    expect(result).toHaveLength(1)
    expect(result[0].advisory.type).toBe('mal')
  })
})
