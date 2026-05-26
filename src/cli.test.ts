import { describe, it, expect, vi, afterEach } from 'vitest'
import { safeClose } from './cli.js'

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
