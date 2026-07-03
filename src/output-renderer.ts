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

// Strip C0/C1 control characters (including ESC 0x1b and BEL) from attacker-influenceable fields
// before writing them to the terminal. Package names, versions, and npm-alias keys (Finding.via)
// flow from the lockfile; raw escape sequences there could clear the screen, reposition the cursor,
// or overlay a fake "clean" summary over real findings. The JSON renderer is unaffected — JSON
// string escaping already neutralizes control characters.
function stripControl(s: string): string {
  let out = ''
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    // Drop C0 controls (0x00–0x1f), DEL (0x7f), and C1 controls (0x80–0x9f); keep everything else.
    if (c > 0x1f && c !== 0x7f && (c < 0x80 || c > 0x9f)) out += ch
  }
  return out
}

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
    schemaVersion: '1',
    findings: findings.map((f) => ({
      name: f.name,
      version: f.version,
      ...(f.via !== undefined ? { via: f.via } : {}),
      advisory: f.advisory,
      fix: firstFixed(f.advisory.ranges),
    })),
    warnings: warnings.map((w) => w.message),
    // Additive (#44): warnings loses ScanWarning.class, forcing consumers to string-match
    // messages to distinguish incomplete (exit 2) from informational notices. warningDetails
    // carries the full ScanWarning alongside the existing field — non-breaking, no schemaVersion
    // bump (see docs/output-schema.md's additive-fields-don't-bump-version rule).
    warningDetails: warnings.map((w) => ({ class: w.class, message: w.message })),
  }
  return JSON.stringify(out, null, 2)
}

export function renderGrouped(findings: Finding[], warnings: ScanWarning[]): string {
  const lines: string[] = []

  if (warnings.length > 0) {
    lines.push(chalk.dim('Warnings:'))
    for (const w of warnings) lines.push(chalk.dim(`  ! ${stripControl(w.message)}`))
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
      const viaStr = sample.via !== undefined ? ` [via ${stripControl(sample.via)}]` : ''
      lines.push(`  ${stripControl(sample.name)}@${stripControl(sample.version)}${viaStr}`)

      for (const pf of pkgFindings) {
        const fix = firstFixedDisplay(pf.advisory.ranges)
        const fixStr = fix !== undefined ? `  → fix: ${fix}` : ''
        const url = canonicalUrl(pf.advisory.id, pf.advisory.url)
        const safeTitle = stripControl(pf.advisory.title)
        const title = safeTitle.length > 60 ? safeTitle.slice(0, 60) + '…' : safeTitle
        lines.push(`    ${stripControl(pf.advisory.id)}  ${title}${fixStr}`)
        lines.push(`    ${stripControl(url)}`)
      }
    }
  }

  lines.push(`\n${findings.length} finding${findings.length === 1 ? '' : 's'}`)

  return lines.join('\n')
}
