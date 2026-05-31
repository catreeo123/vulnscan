import type { Advisory, Severity } from './types.js'
import { informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

/**
 * Resolve the stored severity for an advisory, applying the malware override.
 *
 * Malware advisories (`type === 'mal'`) are always `critical` regardless of the
 * upstream label — feeds frequently omit or under-rate severity for malicious
 * packages. Both the OSV and GitHub Advisory sync paths route through here so the
 * override cannot drift between sources.
 */
export function resolveAdvisorySeverity(
  type: Advisory['type'],
  label: string | undefined,
  advisoryId: string,
): { severity: Severity; warning?: ScanWarning } {
  const { severity, warning } = mapSeverity({ label, advisoryId })
  // Malware is forced to critical regardless of label. The label-default warning ("unknown
  // severity, defaulting to 'high'") would then be factually wrong (the stored severity is
  // critical, not high), so suppress it for mal advisories.
  if (type === 'mal') return { severity: 'critical' }
  return { severity, warning }
}

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
