export type HelpTopic = 'scan' | 'check' | 'update' | 'skill'

export type ParsedArgs =
  | { command: 'scan'; projectDir: string; format: string; failOn: string | null; noSync: boolean }
  | { command: 'check'; target: string; format: string; failOn: string | null; dir: string | null; noSync: boolean }
  | { command: 'update' }
  | { command: 'skill-install' }
  | { command: 'version' }
  | { command: 'help'; topic?: HelpTopic }
  | { command: 'unknown'; raw: string | undefined }

const KNOWN_FLAGS = new Set(['--format', '--fail-on', '--dir'])
const KNOWN_BOOLEAN_FLAGS = new Set(['--offline', '--no-sync'])
const KNOWN_COMMANDS: ReadonlySet<HelpTopic> = new Set(['scan', 'check', 'update', 'skill'])

export function parseArgs(argv: string[]): ParsedArgs {
  if (argv.includes('--version') || argv.includes('-V')) {
    return { command: 'version' }
  }

  if (argv.includes('--help') || argv.includes('-h')) {
    const topic = argv.find((a): a is HelpTopic => KNOWN_COMMANDS.has(a as HelpTopic))
    return topic ? { command: 'help', topic } : { command: 'help' }
  }

  const positional: string[] = []
  const flags: Record<string, string> = {}
  const boolFlags = new Set<string>()

  let i = 0
  while (i < argv.length) {
    const arg = argv[i]
    // Support the `--flag=value` form alongside `--flag value`. Only split on `=` for
    // `--`-prefixed tokens so positionals like `@scope/pkg@1.2.3` are never mangled.
    const eqIdx = arg.startsWith('--') ? arg.indexOf('=') : -1
    const name = eqIdx >= 0 ? arg.slice(0, eqIdx) : arg
    if (KNOWN_BOOLEAN_FLAGS.has(name)) {
      // Boolean flags take no value; `--offline=false` must not silently enable the
      // flag by discarding the value. Warn and ignore rather than invert the intent.
      if (eqIdx >= 0) {
        process.stderr.write(`Warning: ${name} takes no value, ignoring\n`)
      } else {
        boolFlags.add(name)
      }
      i += 1
    } else if (KNOWN_FLAGS.has(name)) {
      if (eqIdx >= 0) {
        const value = arg.slice(eqIdx + 1)
        if (value === '') {
          process.stderr.write(`Warning: ${name} flag has no value, ignoring\n`)
        } else {
          flags[name] = value
        }
        i += 1
      } else {
        const value = argv[i + 1]
        // A next token that is itself a flag (`--`-prefixed) means the value was omitted.
        // Without this guard the flag greedily consumes the following flag — silently storing
        // a flag name as the value AND dropping the consumed flag (e.g. `--format --fail-on x`
        // → format='--fail-on', --fail-on dropped). Treat it as a missing value instead.
        if (value === undefined || value.startsWith('--')) {
          process.stderr.write(`Warning: ${arg} flag has no value, ignoring\n`)
          i += 1
          continue
        }
        flags[name] = value
        i += 2
      }
    } else {
      positional.push(arg)
      i += 1
    }
  }

  const format = flags['--format'] ?? 'table'
  const failOn = flags['--fail-on'] ?? null
  const noSync = boolFlags.has('--offline') || boolFlags.has('--no-sync')

  const cmd = positional[0]

  if (cmd === undefined || cmd === 'scan') {
    return { command: 'scan', projectDir: positional[1] ?? '.', format, failOn, noSync }
  }

  if (cmd === 'update') {
    return { command: 'update' }
  }

  if (cmd === 'skill' && positional[1] === 'install') {
    return { command: 'skill-install' }
  }

  if (cmd === 'check') {
    const target = positional[1] ?? ''
    const dir = flags['--dir'] ?? null
    return { command: 'check', target, format, failOn, dir, noSync }
  }

  return { command: 'unknown', raw: cmd }
}
