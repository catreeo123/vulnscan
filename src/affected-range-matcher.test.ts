import { describe, it, expect } from 'vitest'
import { matchAffected, normalizeRawRange } from './affected-range-matcher.js'
import type { Advisory } from './types.js'

const lodashAdvisory: Advisory = {
  id: 'CVE-2021-23337',
  canonicalId: 'GHSA-35JH-R3H4-6JHM',
  type: 'cve',
  packageName: 'lodash',
  ranges: [{ introduced: '0', fixed: '4.17.21' }],
  severity: 'high',
  title: 'Prototype Pollution',
  url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
}

const malAdvisory: Advisory = {
  id: 'MAL-2024-1234',
  canonicalId: 'MAL-2024-1234',
  type: 'mal',
  packageName: 'malicious-pkg',
  ranges: [{ introduced: '1.0.0' }],
  severity: 'critical',
  title: 'Malicious package: data exfiltration',
  url: 'https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/malicious-pkg/MAL-2024-1234.json',
}

describe('normalizeRawRange', () => {
  it('replaces ", " with a single space (comma+space → space)', () => {
    expect(normalizeRawRange('>= 6.11.1, <= 6.15.1')).toBe('>= 6.11.1 <= 6.15.1')
  })
})

describe('matchAffected', () => {
  it('returns no Finding when installed version is outside affected range', () => {
    const findings = matchAffected({ name: 'lodash', version: '4.17.21' }, [lodashAdvisory])
    expect(findings).toHaveLength(0)
  })

  it('returns a Finding when installed version is within affected range', () => {
    const findings = matchAffected({ name: 'lodash', version: '4.17.20' }, [lodashAdvisory])

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      name: 'lodash',
      version: '4.17.20',
      advisory: expect.objectContaining({ id: 'CVE-2021-23337' }),
    })
  })

  it('matches prerelease versions within the affected range', () => {
    const prereleaseAdvisory: Advisory = {
      id: 'CVE-2024-9999',
      canonicalId: 'CVE-2024-9999',
      type: 'cve',
      packageName: 'some-pkg',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
      severity: 'moderate',
      title: 'Some vuln',
      url: 'https://example.com',
    }

    const findings = matchAffected({ name: 'some-pkg', version: '1.0.0-beta.1' }, [prereleaseAdvisory])

    expect(findings).toHaveLength(1)
  })

  it('returns a single Finding when multiple overlapping ranges all match', () => {
    const multiRangeAdvisory: Advisory = {
      id: 'CVE-2024-0001',
      canonicalId: 'CVE-2024-0001',
      type: 'cve',
      packageName: 'some-pkg',
      ranges: [
        { introduced: '1.0.0', fixed: '1.5.0' },
        { introduced: '1.2.0', fixed: '1.4.0' },
      ],
      severity: 'high',
      title: 'Some vuln',
      url: 'https://example.com',
    }

    const findings = matchAffected({ name: 'some-pkg', version: '1.3.0' }, [multiRangeAdvisory])

    expect(findings).toHaveLength(1)
  })

  it('matches GitHub Advisory comma-separated rawRange (>= x, <= y)', () => {
    const advisory: Advisory = {
      id: 'CVE-2026-4800',
      canonicalId: 'GHSA-R5FR-RJXR-66JC',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ rawRange: '>= 4.0.0, <= 4.17.23' }],
      severity: 'high',
      title: 'lodash code injection',
      url: 'https://github.com/advisories/GHSA-r5fr-rjxr-66jc',
    }
    expect(matchAffected({ name: 'lodash', version: '4.17.21' }, [advisory])).toHaveLength(1)
    expect(matchAffected({ name: 'lodash', version: '4.18.0' }, [advisory])).toHaveLength(0)
  })

  it('returns a Finding with type mal for a MAL-* advisory', () => {
    const findings = matchAffected({ name: 'malicious-pkg', version: '1.2.0' }, [malAdvisory])

    expect(findings).toHaveLength(1)
    expect(findings[0].advisory.type).toBe('mal')
    expect(findings[0].advisory.id).toMatch(/^MAL-/)
  })

  it('returns two findings when two distinct advisories both match', () => {
    const advisory2: Advisory = { ...lodashAdvisory, id: 'CVE-2020-8203' }
    const findings = matchAffected({ name: 'lodash', version: '4.17.20' }, [lodashAdvisory, advisory2])
    expect(findings).toHaveLength(2)
    expect(findings.map((f) => f.advisory.id)).toEqual(['CVE-2021-23337', 'CVE-2020-8203'])
  })

  it('propagates dep.via to each finding', () => {
    const findings = matchAffected({ name: 'lodash', version: '4.17.20', via: 'dd-trace' }, [lodashAdvisory])
    expect(findings[0].via).toBe('dd-trace')
  })

  it('matches when installed version equals introduced (>= is inclusive)', () => {
    const advisory: Advisory = {
      id: 'CVE-2024-1111',
      canonicalId: 'CVE-2024-1111',
      type: 'cve',
      packageName: 'some-pkg',
      ranges: [{ introduced: '1.0.0', fixed: '2.0.0' }],
      severity: 'low',
      title: 'Test',
      url: 'https://example.com',
    }
    const findings = matchAffected({ name: 'some-pkg', version: '1.0.0' }, [advisory])
    expect(findings).toHaveLength(1)
  })

  it('returns no finding when advisory has empty ranges array', () => {
    const advisory: Advisory = {
      id: 'CVE-2024-0000',
      canonicalId: 'CVE-2024-0000',
      type: 'cve',
      packageName: 'some-pkg',
      ranges: [],
      severity: 'low',
      title: 'Test',
      url: 'https://example.com',
    }
    const findings = matchAffected({ name: 'some-pkg', version: '1.0.0' }, [advisory])
    expect(findings).toHaveLength(0)
  })

  it('treats empty-string introduced as "0" — must not silently miss the advisory', () => {
    // An empty-string `introduced` is not null/undefined, so `?? '0'` lets it through and
    // buildSemverRange produces ">= <2.0.0" (invalid). semver.satisfies silently returns
    // false for an invalid range → the vulnerable package is never flagged (false negative).
    const advisory: Advisory = {
      id: 'CVE-EMPTY-INTRO',
      canonicalId: 'CVE-EMPTY-INTRO',
      type: 'cve',
      packageName: 'ei-pkg',
      ranges: [{ introduced: '', fixed: '2.0.0' }],
      severity: 'high',
      title: 'empty introduced',
      url: 'https://example.com',
    }
    expect(matchAffected({ name: 'ei-pkg', version: '1.0.0' }, [advisory])).toHaveLength(1)
  })

  it('lastAffected caps the upper bound: matches versions <=lastAffected', () => {
    const advisory: Advisory = {
      id: 'CVE-LA-1',
      canonicalId: 'CVE-LA-1',
      type: 'cve',
      packageName: 'la-pkg',
      ranges: [{ introduced: '0', lastAffected: '1.2.3' }],
      severity: 'high',
      title: 'last_affected bound test',
      url: 'https://example.com',
    }
    expect(matchAffected({ name: 'la-pkg', version: '1.2.3' }, [advisory])).toHaveLength(1)
    expect(matchAffected({ name: 'la-pkg', version: '1.0.0' }, [advisory])).toHaveLength(1)
  })

  it('lastAffected does NOT match versions strictly greater than lastAffected', () => {
    const advisory: Advisory = {
      id: 'CVE-LA-2',
      canonicalId: 'CVE-LA-2',
      type: 'cve',
      packageName: 'la-pkg',
      ranges: [{ introduced: '0', lastAffected: '1.2.3' }],
      severity: 'high',
      title: 'last_affected bound test',
      url: 'https://example.com',
    }
    expect(matchAffected({ name: 'la-pkg', version: '1.2.4' }, [advisory])).toHaveLength(0)
    expect(matchAffected({ name: 'la-pkg', version: '2.0.0' }, [advisory])).toHaveLength(0)
  })
})
