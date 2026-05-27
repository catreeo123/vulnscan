import chalk from 'chalk'
import type { Finding, Severity } from './types.js'
import type { ScanWarning } from './warnings.js'

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.red.bold(s),
  high: (s) => chalk.hex('#FF8C00')(s),
  moderate: (s) => chalk.yellow(s),
  low: (s) => chalk.gray(s),
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low']

function canonicalUrl(id: string, fallback: string): string {
  if (id.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${id}`
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`
  return fallback
}

// Returns a version string for JSON output (omits <= ranges — no clean semver version).
function firstFixed(ranges: Array<{ introduced?: string; fixed?: string; rawRange?: string }>): string | undefined {
  for (const r of ranges) {
    if (r.fixed) return r.fixed
    if (r.rawRange) {
      const m = r.rawRange.match(/<(?!=)\s*([\d][^\s,]*)/)
      if (m) return m[1]
    }
  }
  return undefined
}

// Returns a display string for grouped output, e.g. "≥1.2.0" or ">0.24.2".
function firstFixedDisplay(ranges: Array<{ introduced?: string; fixed?: string; rawRange?: string }>): string | undefined {
  for (const r of ranges) {
    if (r.fixed) return `≥${r.fixed}`
    if (r.rawRange) {
      const excl = r.rawRange.match(/<(?!=)\s*([\d][^\s,]*)/)
      if (excl) return `≥${excl[1]}`
      const incl = r.rawRange.match(/<=\s*([\d][^\s,]*)/)
      if (incl) return `>${incl[1]}`
    }
  }
  return undefined
}

export function renderJson(findings: Finding[], warnings: ScanWarning[]): string {
  const out = {
    findings: findings.map((f) => ({
      name: f.name,
      version: f.version,
      ...(f.via !== undefined ? { via: f.via } : {}),
      advisory: f.advisory,
      fix: firstFixed(f.advisory.ranges),
    })),
    warnings: warnings.map((w) => w.message),
  }
  return JSON.stringify(out, null, 2)
}

export function renderGrouped(findings: Finding[], warnings: ScanWarning[]): string {
  const lines: string[] = []

  if (warnings.length > 0) {
    lines.push(chalk.dim('Warnings:'))
    for (const w of warnings) lines.push(chalk.dim(`  ! ${w.message}`))
    lines.push('')
  }

  if (findings.length === 0) {
    lines.push(chalk.green('✓ No findings'))
    return lines.join('\n')
  }

  // Group by severity
  const bySeverity = new Map<Severity, Finding[]>()
  for (const sev of SEVERITY_ORDER) bySeverity.set(sev, [])
  for (const f of findings) {
    bySeverity.get(f.advisory.severity)!.push(f)
  }

  for (const sev of SEVERITY_ORDER) {
    const group = bySeverity.get(sev)!
    if (group.length === 0) continue

    const colorize = SEVERITY_COLOR[sev]
    lines.push(colorize(`\n${sev.toUpperCase()} (${group.length})`))

    // Group by package name within this severity
    const byPkg = new Map<string, Finding[]>()
    for (const f of group) {
      const key = `${f.name}@${f.version}`
      if (!byPkg.has(key)) byPkg.set(key, [])
      byPkg.get(key)!.push(f)
    }

    for (const [, pkgFindings] of byPkg) {
      const sample = pkgFindings[0]
      const viaStr = sample.via !== undefined ? ` [via ${sample.via}]` : ''
      lines.push(`  ${sample.name}@${sample.version}${viaStr}`)

      for (const pf of pkgFindings) {
        const fix = firstFixedDisplay(pf.advisory.ranges)
        const fixStr = fix !== undefined ? `  → fix: ${fix}` : ''
        const url = canonicalUrl(pf.advisory.id, pf.advisory.url)
        const title = pf.advisory.title.length > 60 ? pf.advisory.title.slice(0, 60) + '…' : pf.advisory.title
        lines.push(`    ${pf.advisory.id}  ${title}${fixStr}`)
        lines.push(`    ${url}`)
      }
    }
  }

  lines.push(`\n${findings.length} finding${findings.length === 1 ? '' : 's'}`)

  return lines.join('\n')
}
