export type HelpTopic = 'scan' | 'check' | 'update'

export type ParsedArgs =
  | { command: 'scan'; projectDir: string; format: string; failOn: string | null; noSync: boolean }
  | { command: 'check'; target: string; format: string; failOn: string | null; dir: string | null; noSync: boolean }
  | { command: 'update' }
  | { command: 'help'; topic?: HelpTopic }
  | { command: 'unknown'; raw: string | undefined }

const KNOWN_FLAGS = new Set(['--format', '--fail-on', '--dir'])
const KNOWN_BOOLEAN_FLAGS = new Set(['--offline', '--no-sync'])
const KNOWN_COMMANDS: ReadonlySet<HelpTopic> = new Set(['scan', 'check', 'update'])

export function parseArgs(argv: string[]): ParsedArgs {
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
    if (KNOWN_BOOLEAN_FLAGS.has(arg)) {
      boolFlags.add(arg)
      i += 1
    } else if (KNOWN_FLAGS.has(arg)) {
      const value = argv[i + 1]
      if (value === undefined) {
        process.stderr.write(`Warning: ${arg} flag has no value, ignoring\n`)
        i += 1
        continue
      }
      flags[arg] = value
      i += 2
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

  if (cmd === 'check') {
    const target = positional[1] ?? ''
    const dir = flags['--dir'] ?? null
    return { command: 'check', target, format, failOn, dir, noSync }
  }

  return { command: 'unknown', raw: cmd }
}
