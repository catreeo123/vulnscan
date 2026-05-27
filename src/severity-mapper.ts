import type { Severity } from './types.js'
import { informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

export function mapSeverity(input: {
  label?: string
  advisoryId: string
}): { severity: Severity; warning?: ScanWarning } {
  const { label, advisoryId } = input
  const u = label?.toUpperCase() ?? ''

  if (u === 'CRITICAL') return { severity: 'critical' }
  if (u === 'HIGH') return { severity: 'high' }
  if (u === 'MODERATE' || u === 'MEDIUM') return { severity: 'moderate' }
  if (u === 'LOW') return { severity: 'low' }

  // Unknown or missing: fail-safe escalation to high
  return {
    severity: 'high',
    warning: informational(
      `Advisory ${advisoryId} has unknown or missing severity metadata; defaulting to 'high' (fail-safe escalation)`,
    ),
  }
}
