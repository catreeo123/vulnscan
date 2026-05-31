import { describe, it, expect } from 'vitest'
import { assembleAdvisories, type AdvisoryIdentity, type PackageContribution } from './advisory-assembler.js'

const identity: AdvisoryIdentity = {
  id: 'CVE-2021-1234',
  canonicalId: 'GHSA-aaaa-bbbb-cccc',
  type: 'cve',
  title: 'a vulnerability',
  url: 'https://example.test/CVE-2021-1234',
}

describe('assembleAdvisories', () => {
  it('emits one Advisory per package carrying the shared identity fields', () => {
    const contributions: PackageContribution[] = [
      { packageName: 'lodash', ranges: [{ introduced: '0', fixed: '4.17.21' }], severity: 'high' },
    ]
    const result = assembleAdvisories(identity, contributions)
    expect(result).toEqual([
      {
        id: 'CVE-2021-1234',
        canonicalId: 'GHSA-aaaa-bbbb-cccc',
        type: 'cve',
        packageName: 'lodash',
        ranges: [{ introduced: '0', fixed: '4.17.21' }],
        severity: 'high',
        title: 'a vulnerability',
        url: 'https://example.test/CVE-2021-1234',
      },
    ])
  })

  it('unions ranges for the same package into a single Advisory (no range is lost)', () => {
    // The whole point of #48/B1: two affected blocks for one package must NOT collapse
    // to the last block under the (id, packageName) upsert.
    const contributions: PackageContribution[] = [
      { packageName: 'lodash', ranges: [{ introduced: '0', fixed: '4.17.11' }], severity: 'high' },
      { packageName: 'lodash', ranges: [{ introduced: '4.17.12', fixed: '4.17.21' }], severity: 'high' },
    ]
    const result = assembleAdvisories(identity, contributions)
    expect(result).toHaveLength(1)
    expect(result[0].ranges).toEqual([
      { introduced: '0', fixed: '4.17.11' },
      { introduced: '4.17.12', fixed: '4.17.21' },
    ])
  })

  it('keeps the most severe rating seen across contributions for the same package', () => {
    const contributions: PackageContribution[] = [
      { packageName: 'lodash', ranges: [{ rawRange: '<1.0.0' }], severity: 'low' },
      { packageName: 'lodash', ranges: [{ rawRange: '>=1.0.0 <2.0.0' }], severity: 'critical' },
      { packageName: 'lodash', ranges: [{ rawRange: '>=2.0.0 <3.0.0' }], severity: 'moderate' },
    ]
    const result = assembleAdvisories(identity, contributions)
    expect(result).toHaveLength(1)
    expect(result[0].severity).toBe('critical')
  })

  it('produces a separate Advisory per package, preserving first-occurrence order', () => {
    const contributions: PackageContribution[] = [
      { packageName: 'beta', ranges: [{ rawRange: '<1' }], severity: 'high' },
      { packageName: 'alpha', ranges: [{ rawRange: '<1' }], severity: 'high' },
      { packageName: 'beta', ranges: [{ rawRange: '>=1 <2' }], severity: 'high' },
    ]
    const result = assembleAdvisories(identity, contributions)
    expect(result.map((a) => a.packageName)).toEqual(['beta', 'alpha'])
    expect(result[0].ranges).toHaveLength(2)
  })

  it('drops contributions with no ranges — an empty-range Advisory can never match', () => {
    const contributions: PackageContribution[] = [
      { packageName: 'lodash', ranges: [], severity: 'high' },
    ]
    expect(assembleAdvisories(identity, contributions)).toEqual([])
  })
})
