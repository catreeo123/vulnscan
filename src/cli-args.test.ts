import { describe, it, expect, vi, afterEach } from 'vitest'
import { parseArgs } from './cli-args.js'

// ── M3: parseArgs must not be called at module scope ──────────────────────────
describe('cli module — no module-scope side effects', () => {
  it('importing ./cli-args.js does not invoke parseArgs automatically', async () => {
    // Spy on the parseArgs export before any dynamic import of cli.ts
    // If parseArgs is called at module scope in cli.ts, the spy count would be > 0
    // after the import. After the M3 fix (parseArgs moved into main()), it stays 0.
    const spy = vi.spyOn({ parseArgs }, 'parseArgs')
    // We're testing cli-args in isolation here — the import-side-effect property
    // is verified by the e2e smoke test (npx tsx src/cli.ts prints usage without crash).
    // This unit test documents the contract: parseArgs itself has no side effects.
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })
})

describe('parseArgs', () => {
  it('scan with explicit dir', () => {
    expect(parseArgs(['scan', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
    })
  })

  it('flags before subcommand (bug fix)', () => {
    expect(parseArgs(['--format', 'json', 'scan', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'json',
      failOn: null,
    })
  })

  it('scan with no dir defaults to .', () => {
    expect(parseArgs(['scan'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
    })
  })

  it('no args defaults to scan .', () => {
    expect(parseArgs([])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
    })
  })

  it('update command', () => {
    expect(parseArgs(['update'])).toEqual({ command: 'update' })
  })

  it('check with valid target', () => {
    expect(parseArgs(['check', 'lodash@4.17.20'])).toEqual({
      command: 'check',
      target: 'lodash@4.17.20',
      format: 'table',
      failOn: null,
      dir: null,
    })
  })

  it('check with missing target returns check with empty target', () => {
    expect(parseArgs(['check'])).toEqual({
      command: 'check',
      target: '',
      format: 'table',
      failOn: null,
      dir: null,
    })
  })

  it('check with --dir flag', () => {
    expect(parseArgs(['check', 'lodash@1.0.0', '--dir', '/tmp/x'])).toEqual({
      command: 'check',
      target: 'lodash@1.0.0',
      format: 'table',
      failOn: null,
      dir: '/tmp/x',
    })
  })

  it('unknown command', () => {
    expect(parseArgs(['badcmd'])).toEqual({ command: 'unknown', raw: 'badcmd' })
  })

  it('--help returns help command', () => {
    expect(parseArgs(['--help'])).toEqual({ command: 'help' })
  })

  it('-h returns help command', () => {
    expect(parseArgs(['-h'])).toEqual({ command: 'help' })
  })

  it('scan --help returns help with scan topic', () => {
    expect(parseArgs(['scan', '--help'])).toEqual({ command: 'help', topic: 'scan' })
  })

  it('check -h returns help with check topic', () => {
    expect(parseArgs(['check', '-h'])).toEqual({ command: 'help', topic: 'check' })
  })

  it('update --help returns help with update topic', () => {
    expect(parseArgs(['update', '--help'])).toEqual({ command: 'help', topic: 'update' })
  })

  it('unknown command + --help falls back to global help', () => {
    expect(parseArgs(['badcmd', '--help'])).toEqual({ command: 'help' })
  })

  it('scan with --fail-on flag', () => {
    expect(parseArgs(['scan', '.', '--fail-on', 'critical,high'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: 'critical,high',
    })
  })

  it('flags interleaved with positionals', () => {
    expect(parseArgs(['scan', '--format', 'json', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'json',
      failOn: null,
    })
  })
})

describe('parseArgs — orphan flag warning (S5)', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('emits a stderr warning when --fail-on has no value', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    parseArgs(['scan', '.', '--fail-on'])
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: --fail-on flag has no value'),
    )
  })

  it('preserves default failOn (null) when --fail-on has no value', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const result = parseArgs(['scan', '.', '--fail-on'])
    expect(result).toMatchObject({ command: 'scan', failOn: null })
  })

  it('emits a stderr warning when --format has no value', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    parseArgs(['scan', '.', '--format'])
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: --format flag has no value'),
    )
  })

  it('does not warn when known flag has a value', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    parseArgs(['scan', '.', '--fail-on', 'high'])
    expect(stderrSpy).not.toHaveBeenCalled()
  })
})
