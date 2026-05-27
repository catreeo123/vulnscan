import { describe, it, expect, vi, afterEach } from 'vitest'
import { safeClose, computeExitCode } from './cli.js'
import type { Finding } from './types.js'
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
})

describe('safeClose', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('does not throw when db.close() throws', () => {
    const mockDb = { close: () => { throw new Error('SQLITE_BUSY: database is locked') } } as any
    expect(() => safeClose(mockDb)).not.toThrow()
  })

  it('writes a warning to stderr when db.close() throws', () => {
    const mockDb = { close: () => { throw new Error('SQLITE_BUSY') } } as any
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    safeClose(mockDb)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('Warning: db.close failed'))
  })

  it('includes the error message in the warning', () => {
    const mockDb = { close: () => { throw new Error('SQLITE_BUSY') } } as any
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    safeClose(mockDb)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('SQLITE_BUSY'))
  })

  it('calls db.close() normally when it does not throw', () => {
    const closeSpy = vi.fn()
    const mockDb = { close: closeSpy } as any
    safeClose(mockDb)
    expect(closeSpy).toHaveBeenCalledOnce()
  })
})
