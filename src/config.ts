import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import type { Severity } from './types.js'

export type Config = {
  failOn: Severity[]
  stalenessHours: number
  stalenessMs: number
}

const DEFAULTS: Config = {
  failOn: ['critical', 'high'],
  stalenessHours: 24,
  stalenessMs: 24 * 60 * 60 * 1000,
}

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low']

export function validateFailOn(raw: unknown): Severity[] {
  if (!Array.isArray(raw)) return DEFAULTS.failOn
  const valid: Severity[] = []
  const invalid: string[] = []
  for (const item of raw) {
    if (typeof item === 'string' && (VALID_SEVERITIES as string[]).includes(item)) {
      valid.push(item as Severity)
    } else {
      invalid.push(String(item))
    }
  }
  if (invalid.length > 0) {
    process.stderr.write(`Warning: .vulnscanrc failOn contains invalid severities: ${invalid.join(', ')} (valid: ${VALID_SEVERITIES.join(', ')})\n`)
  }
  return valid.length > 0 ? valid : DEFAULTS.failOn
}

function validateStalenessHours(raw: unknown): number {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) {
    return raw
  }
  if (raw !== undefined) {
    process.stderr.write(`Warning: .vulnscanrc stalenessHours is invalid (${JSON.stringify(raw)}), using default ${DEFAULTS.stalenessHours}\n`)
  }
  return DEFAULTS.stalenessHours
}

export function loadConfig(projectDir: string): Config {
  const locations = [join(projectDir, '.vulnscanrc'), join(homedir(), '.vulnscanrc')]

  for (const loc of locations) {
    try {
      const raw = readFileSync(loc, 'utf8')
      const parsed = JSON.parse(raw) as Record<string, unknown>
      const stalenessHours = validateStalenessHours(parsed.stalenessHours)
      return {
        failOn: validateFailOn(parsed.failOn),
        stalenessHours,
        stalenessMs: stalenessHours * 60 * 60 * 1000,
      }
    } catch {
      // file not found or invalid JSON — try next location
    }
  }

  return { ...DEFAULTS }
}
