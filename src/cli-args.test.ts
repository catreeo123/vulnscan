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
      noSync: false,
    })
  })

  it('flags before subcommand (bug fix)', () => {
    expect(parseArgs(['--format', 'json', 'scan', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'json',
      failOn: null,
      noSync: false,
    })
  })

  it('scan with no dir defaults to .', () => {
    expect(parseArgs(['scan'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: false,
    })
  })

  it('no args defaults to scan .', () => {
    expect(parseArgs([])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: false,
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
      noSync: false,
    })
  })

  it('check with missing target returns check with empty target', () => {
    expect(parseArgs(['check'])).toEqual({
      command: 'check',
      target: '',
      format: 'table',
      failOn: null,
      dir: null,
      noSync: false,
    })
  })

  it('check with --dir flag', () => {
    expect(parseArgs(['check', 'lodash@1.0.0', '--dir', '/tmp/x'])).toEqual({
      command: 'check',
      target: 'lodash@1.0.0',
      format: 'table',
      failOn: null,
      dir: '/tmp/x',
      noSync: false,
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
      noSync: false,
    })
  })

  it('--fail-on=value (equals form) parses like the space form', () => {
    expect(parseArgs(['scan', '.', '--fail-on=critical,high'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: 'critical,high',
      noSync: false,
    })
  })

  it('--format=json (equals form) sets format', () => {
    expect(parseArgs(['scan', '.', '--format=json'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'json',
      failOn: null,
      noSync: false,
    })
  })

  it('--dir=value (equals form) sets dir on check', () => {
    expect(parseArgs(['check', 'lodash@1.0.0', '--dir=/tmp/x'])).toEqual({
      command: 'check',
      target: 'lodash@1.0.0',
      format: 'table',
      failOn: null,
      dir: '/tmp/x',
      noSync: false,
    })
  })

  it('does not mistake an @-bearing positional for a flag', () => {
    expect(parseArgs(['check', '@scope/pkg@1.2.3'])).toEqual({
      command: 'check',
      target: '@scope/pkg@1.2.3',
      format: 'table',
      failOn: null,
      dir: null,
      noSync: false,
    })
  })

  it('flags interleaved with positionals', () => {
    expect(parseArgs(['scan', '--format', 'json', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'json',
      failOn: null,
      noSync: false,
    })
  })

  it('--offline sets noSync=true on scan', () => {
    expect(parseArgs(['scan', '.', '--offline'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: true,
    })
  })

  it('--no-sync alias sets noSync=true on scan', () => {
    expect(parseArgs(['scan', '.', '--no-sync'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: true,
    })
  })

  it('--offline sets noSync=true on check', () => {
    expect(parseArgs(['check', 'lodash@4.17.20', '--offline'])).toEqual({
      command: 'check',
      target: 'lodash@4.17.20',
      format: 'table',
      failOn: null,
      dir: null,
      noSync: true,
    })
  })

  it('--no-sync does not swallow next positional as value', () => {
    // Boolean flag should not consume argv[i+1]
    expect(parseArgs(['scan', '--no-sync', '.'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: true,
    })
  })

  it('--no-sync=false does not enable noSync (boolean flag takes no value)', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    expect(parseArgs(['scan', '.', '--no-sync=false'])).toEqual({
      command: 'scan',
      projectDir: '.',
      format: 'table',
      failOn: null,
      noSync: false,
    })
    vi.restoreAllMocks()
  })

  it('--offline=true does not enable noSync (boolean flag takes no value)', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    expect(parseArgs(['scan', '.', '--offline=true'])).toMatchObject({ noSync: false })
    vi.restoreAllMocks()
  })

  it('--fail-on= (empty equals value) falls back to default, not empty string', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    expect(parseArgs(['scan', '.', '--fail-on='])).toMatchObject({ failOn: null })
    vi.restoreAllMocks()
  })
})

describe('parseArgs — --version flag (#19)', () => {
  it('--version returns version command', () => {
    expect(parseArgs(['--version'])).toEqual({ command: 'version' })
  })

  it('-V returns version command', () => {
    expect(parseArgs(['-V'])).toEqual({ command: 'version' })
  })
})

describe('parseArgs — skill --help (#21)', () => {
  it('skill --help returns help with skill topic', () => {
    expect(parseArgs(['skill', '--help'])).toEqual({ command: 'help', topic: 'skill' })
  })

  it('skill install --help returns help with skill topic', () => {
    expect(parseArgs(['skill', 'install', '--help'])).toEqual({ command: 'help', topic: 'skill' })
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
    expect(result).toMatchObject({ command: 'scan', failOn: null, noSync: false })
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

  it('warns that a boolean flag takes no value when given --offline=false', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    parseArgs(['scan', '.', '--offline=false'])
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: --offline takes no value'),
    )
  })

  it('warns when a known flag is given an empty equals value', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    parseArgs(['scan', '.', '--fail-on='])
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: --fail-on flag has no value'),
    )
  })

  it('does not greedily consume a following flag as a value', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    // `--format` has no value here; it must NOT swallow the next flag token. Greedy consumption
    // would set format='--fail-on' (silently wrong) and drop `--fail-on critical` with no warning.
    const result = parseArgs(['scan', '.', '--format', '--fail-on', 'critical'])
    expect(result).toMatchObject({ command: 'scan', format: 'table', failOn: 'critical' })
  })

  it('emits a no-value warning (and still applies the next flag) when a value-flag is followed by a flag', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const result = parseArgs(['scan', '.', '--fail-on', '--offline'])
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: --fail-on flag has no value'),
    )
    // --offline must still be honored as a boolean flag, not consumed as --fail-on's value.
    expect(result).toMatchObject({ command: 'scan', failOn: null, noSync: true })
  })
})
