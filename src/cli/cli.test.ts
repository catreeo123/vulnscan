import { describe, it, expect, vi, afterEach } from 'vitest'
import { safeClose, computeExitCode, run } from './cli.js'
import type { Finding } from '../core/types.js'
import { incomplete, informational } from '../core/warnings.js'
import type { ScanWarning } from '../core/warnings.js'

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

// GAP #5: renderHelp content contract — pure string function, zero tests before this
// Tested via run() since renderHelp is not exported; help branch has no DB or network calls
describe('renderHelp content — via run()', () => {
  async function captureStdout(fn: () => Promise<unknown>): Promise<string> {
    const written: string[] = []
    const orig = process.stdout.write.bind(process.stdout)
    ;(process.stdout as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    try {
      await fn()
    } finally {
      ;(process.stdout as any).write = orig
    }
    return written.join('')
  }

  it('global --help lists all four subcommands and returns 0', async () => {
    const code = await run(['--help'])
    expect(code).toBe(0)
  })

  it('global --help lists scan, check, update, and skill', async () => {
    const out = await captureStdout(() => run(['--help']))
    expect(out).toMatch(/\[scan\]/)     // scan is default command shown as [scan]
    expect(out).toMatch(/vulnscan check/)
    expect(out).toMatch(/vulnscan update/)
    expect(out).toMatch(/vulnscan skill/)
  })

  it('scan --help includes --fail-on option and exit code priority note', async () => {
    const out = await captureStdout(() => run(['scan', '--help']))
    expect(out).toMatch(/--fail-on/)
    expect(out).toMatch(/exit 2 takes priority/)
  })

  it('check --help includes --dir option', async () => {
    const out = await captureStdout(() => run(['check', '--help']))
    expect(out).toMatch(/--dir/)
  })

  it('update --help includes environment and force re-sync note', async () => {
    const out = await captureStdout(() => run(['update', '--help']))
    expect(out).toMatch(/force a full re-sync/)
    expect(out).toMatch(/VULNSCAN_DB_PATH/)
  })

  it('skill --help includes install subcommand', async () => {
    const out = await captureStdout(() => run(['skill', '--help']))
    expect(out).toMatch(/install/)
  })
})

describe('run() — version command', () => {
  it('--version outputs the package version and returns 0', async () => {
    const written: string[] = []
    const orig = process.stdout.write.bind(process.stdout)
    ;(process.stdout as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    const code = await run(['--version'])
    ;(process.stdout as any).write = orig
    expect(code).toBe(0)
    expect(written.join('')).toMatch(/^\d+\.\d+\.\d+/)
  })
})

describe('run() — check usage guard', () => {
  // These return before maybeBootstrap/openStore, so no network or DB is touched.
  it('returns 1 for a scoped package with no version (@scope/pkg)', async () => {
    const code = await run(['check', '@scope/pkg'])
    expect(code).toBe(1)
  })

  it('returns 1 for a bare package with no version', async () => {
    const code = await run(['check', 'lodash'])
    expect(code).toBe(1)
  })

  it('writes the usage hint to stderr for a versionless scoped package', async () => {
    const written: string[] = []
    const orig = process.stderr.write.bind(process.stderr)
    ;(process.stderr as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    await run(['check', '@scope/pkg'])
    ;(process.stderr as any).write = orig
    expect(written.join('')).toMatch(/Usage: vulnscan check/)
  })
})

describe('run() — unknown command', () => {
  it('returns 1 for an unrecognised command', async () => {
    const code = await run(['__definitely_not_a_command__'])
    expect(code).toBe(1)
  })

  it('writes "Unknown command" to stderr for an unrecognised command', async () => {
    const written: string[] = []
    const orig = process.stderr.write.bind(process.stderr)
    ;(process.stderr as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }
    await run(['__definitely_not_a_command__'])
    ;(process.stderr as any).write = orig
    expect(written.join('')).toMatch(/Unknown command/)
  })
})
