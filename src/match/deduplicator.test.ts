import { describe, it, expect } from 'vitest'
import { deduplicate } from './deduplicator.js'
import type { Finding } from '../core/types.js'

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
})
