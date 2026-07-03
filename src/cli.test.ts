import { describe, it, expect, vi, afterEach } from 'vitest'
import { safeClose, run } from './cli.js'

// computeExitCode / resolveFailOn threshold semantics now live in
// ./failure-threshold.test.ts (the policy moved out of cli.ts per #51).

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
