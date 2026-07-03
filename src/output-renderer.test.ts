import { describe, it, expect } from 'vitest'
import { renderGrouped, renderJson } from './output-renderer.js'
import type { Finding } from './types.js'
import { incomplete, informational } from './warnings.js'

// Minimal advisory factory
function mkAdvisory(overrides: Partial<{
  id: string
  severity: 'critical' | 'high' | 'moderate' | 'low'
  title: string
  ranges: Array<{ introduced?: string; fixed?: string; rawRange?: string }>
}> = {}) {
  const id = overrides.id ?? 'CVE-2021-00001'
  return {
    id,
    canonicalId: id,
    type: 'cve' as const,
    packageName: 'pkg',
    ranges: overrides.ranges ?? [{ introduced: '0', fixed: '1.0.0' }],
    severity: overrides.severity ?? 'high',
    title: overrides.title ?? 'A vulnerability',
    url: 'https://example.com',
  }
}

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    name: 'pkg',
    version: '0.9.0',
    advisory: mkAdvisory(),
    ...overrides,
  }
}

// ── Behavior 1: Empty findings ────────────────────────────────────────────────

describe('renderGrouped', () => {
  it('returns "No findings" message when findings list is empty', () => {
    const output = renderGrouped([], [])
    expect(output.toLowerCase()).toContain('no findings')
  })

  // ── Behavior 2: One critical finding has CRITICAL header ──────────────────

  it('output contains CRITICAL header before package name for a critical finding', () => {
    const finding = mkFinding({
      name: 'lodash',
      advisory: mkAdvisory({ severity: 'critical', id: 'CVE-2021-00001' }),
    })
    const output = renderGrouped([finding], [])
    const critIdx = output.indexOf('CRITICAL')
    const pkgIdx = output.indexOf('lodash')
    expect(critIdx).toBeGreaterThanOrEqual(0)
    expect(pkgIdx).toBeGreaterThan(critIdx)
  })

  // ── Behavior 3: Severity order ────────────────────────────────────────────

  it('outputs critical before high before moderate before low', () => {
    const findings: Finding[] = [
      mkFinding({ name: 'low-pkg', advisory: mkAdvisory({ severity: 'low', id: 'CVE-2021-00004' }) }),
      mkFinding({ name: 'moderate-pkg', advisory: mkAdvisory({ severity: 'moderate', id: 'CVE-2021-00003' }) }),
      mkFinding({ name: 'high-pkg', advisory: mkAdvisory({ severity: 'high', id: 'CVE-2021-00002' }) }),
      mkFinding({ name: 'critical-pkg', advisory: mkAdvisory({ severity: 'critical', id: 'CVE-2021-00001' }) }),
    ]
    const output = renderGrouped(findings, [])
    const critIdx = output.indexOf('CRITICAL')
    const highIdx = output.indexOf('HIGH')
    const modIdx = output.indexOf('MODERATE')
    const lowIdx = output.indexOf('LOW')
    expect(critIdx).toBeLessThan(highIdx)
    expect(highIdx).toBeLessThan(modIdx)
    expect(modIdx).toBeLessThan(lowIdx)
  })

  // ── Behavior 4: Package grouping within severity ──────────────────────────

  it('each package appears once per severity group with CVEs indented beneath', () => {
    const advisory1 = mkAdvisory({ id: 'CVE-2021-00001', severity: 'high' })
    const advisory2 = mkAdvisory({ id: 'CVE-2021-00002', severity: 'high' })
    const findings: Finding[] = [
      { name: 'lodash', version: '4.17.20', advisory: advisory1 },
      { name: 'lodash', version: '4.17.20', advisory: advisory2 },
    ]
    const output = renderGrouped(findings, [])
    // lodash appears exactly once as a package line
    const matches = [...output.matchAll(/lodash/g)]
    expect(matches.length).toBe(1)
    // Both CVE IDs appear in output
    expect(output).toContain('CVE-2021-00001')
    expect(output).toContain('CVE-2021-00002')
  })

  // ── Behavior 4b: Different versions of same package → separate entries ───

  it('two different versions of same package appear as separate entries', () => {
    const findings: Finding[] = [
      { name: 'lodash', version: '4.17.19', advisory: mkAdvisory({ id: 'CVE-2021-00001', severity: 'high' }) },
      { name: 'lodash', version: '4.17.20', advisory: mkAdvisory({ id: 'CVE-2021-00002', severity: 'high' }) },
    ]
    const output = renderGrouped(findings, [])
    expect(output).toContain('lodash@4.17.19')
    expect(output).toContain('lodash@4.17.20')
  })

  // ── Behavior 5: Fix annotation when fixed is present ─────────────────────

  it('output contains fix annotation when advisory ranges has a fixed field', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ introduced: '0', fixed: '4.17.21' }] }),
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('→ fix: ≥4.17.21')
  })

  // ── Behavior 5b: Fix extracted from rawRange exclusive upper bound ──────────

  it('rawRange "< X.Y.Z" produces fix annotation ≥X.Y.Z', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ rawRange: '< 4.17.21' }] }),
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('→ fix: ≥4.17.21')
  })

  it('rawRange ">= 1.0.0, < 1.2.0" extracts exclusive upper bound as fix', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ rawRange: '>= 1.0.0, < 1.2.0' }] }),
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('→ fix: ≥1.2.0')
  })

  it('rawRange "<= X.Y.Z" (inclusive) shows >X.Y.Z fix annotation', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ rawRange: '<= 0.24.2' }] }),
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('→ fix: >0.24.2')
  })

  // ── Behavior 6: Fix annotation absent when no fixed field ─────────────────

  it('output has no fix annotation when rawRange has no upper bound', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ rawRange: '>= 1.0.0' }] }),
    })
    const output = renderGrouped([finding], [])
    expect(output).not.toContain('→ fix:')
  })

  // ── Behavior 7: via annotation ────────────────────────────────────────────

  it('package line contains [via <root>] when finding.via is set', () => {
    const finding: Finding = {
      name: 'lodash',
      version: '4.17.20',
      via: 'dd-trace',
      advisory: mkAdvisory(),
    }
    const output = renderGrouped([finding], [])
    expect(output).toContain('[via dd-trace]')
  })

  it('output has no [via text when via is undefined', () => {
    const finding: Finding = {
      name: 'lodash',
      version: '4.17.20',
      advisory: mkAdvisory(),
    }
    const output = renderGrouped([finding], [])
    expect(output).not.toContain('[via')
  })

  // ── Behavior 8: Canonical URL ─────────────────────────────────────────────

  it('CVE ID produces NVD URL', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ id: 'CVE-2021-23337' }),
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('nvd.nist.gov/vuln/detail/CVE-')
  })

  it('GHSA ID produces GitHub advisories URL', () => {
    const finding = mkFinding({
      advisory: {
        id: 'GHSA-35jh-r3h4-6jhm',
        canonicalId: 'GHSA-35JH-R3H4-6JHM',
        type: 'cve',
        packageName: 'pkg',
        ranges: [{ introduced: '0', fixed: '1.0.0' }],
        severity: 'high',
        title: 'Some vuln',
        url: 'https://example.com',
      },
    })
    const output = renderGrouped([finding], [])
    expect(output).toContain('github.com/advisories/GHSA-')
  })

  // ── Behavior 9: MAL-* fallback URL ────────────────────────────────────────

  it('MAL-* advisory uses advisory.url as canonical URL', () => {
    const malUrl = 'https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/evil-pkg/MAL-2024-1234.json'
    const finding: Finding = {
      name: 'evil-pkg',
      version: '1.0.0',
      advisory: {
        id: 'MAL-2024-1234',
        canonicalId: 'MAL-2024-1234',
        type: 'mal',
        packageName: 'evil-pkg',
        ranges: [{ introduced: '1.0.0' }],
        severity: 'critical',
        title: 'Malicious package',
        url: malUrl,
      },
    }
    const output = renderGrouped([finding], [])
    expect(output).toContain('github.com/ossf/malicious-packages')
  })

  // ── Behavior 10: Warnings section ────────────────────────────────────────

  it('renders warnings before findings when warnings are present', () => {
    const output = renderGrouped([mkFinding()], [incomplete('advisory DB may be stale')])
    expect(output).toContain('! advisory DB may be stale')
    expect(output.indexOf('advisory DB')).toBeLessThan(output.indexOf('pkg'))
  })

  // ── Behavior 11: Title truncation ────────────────────────────────────────

  it('truncates advisory title to 60 characters in output', () => {
    const longTitle = 'A'.repeat(80)
    const finding = mkFinding({ advisory: mkAdvisory({ title: longTitle }) })
    const output = renderGrouped([finding], [])
    expect(output).toContain('A'.repeat(60))
    expect(output).not.toContain('A'.repeat(61))
  })

  // ── Behavior 11b: Ellipsis on truncated title ────────────────────────────

  it('appends ellipsis after 60 chars when title is longer than 60 chars', () => {
    const longTitle = 'B'.repeat(80)
    const finding = mkFinding({ advisory: mkAdvisory({ title: longTitle }) })
    const output = renderGrouped([finding], [])
    expect(output).toContain('B'.repeat(60) + '…')
  })

  it('does not append ellipsis when title is 30 chars or fewer', () => {
    const shortTitle = 'C'.repeat(30)
    const finding = mkFinding({ advisory: mkAdvisory({ title: shortTitle }) })
    const output = renderGrouped([finding], [])
    expect(output).toContain(shortTitle)
    expect(output).not.toContain('…')
  })

  // ── Behavior 12: Singular count ──────────────────────────────────────────

  it('shows "1 finding" (singular) when exactly one finding', () => {
    const output = renderGrouped([mkFinding()], [])
    expect(output).toContain('1 finding')
    expect(output).not.toContain('1 findings')
  })

  // ── Behavior 13: Terminal escape sanitization (output spoofing) ───────────────

  it('strips terminal control sequences from attacker-influenced fields', () => {
    // Finding.name/version/via and advisory.id/title/url derive from lockfile + advisory data,
    // some of it attacker-influenceable (e.g. an npm alias key becomes `via`). Raw ANSI/OSC
    // sequences interpolated into the text renderer let a crafted lockfile clear the screen,
    // reposition the cursor, or overlay a fake "clean" summary over real findings. They must be
    // stripped. (chalk only emits SGR `ESC[..m`; the ED/CUP/OSC/BEL sequences below never come
    // from chalk, so asserting their absence is robust whether or not colour is enabled.)
    const finding: Finding = {
      name: 'evil[2J[H',           // clear screen + cursor home
      version: '1.0.0',
      via: ']0;pwned',             // OSC window-title + BEL
      advisory: mkAdvisory({ severity: 'high', id: 'CVE-2099-9999', title: 'x[1;31my' }),
    }
    const output = renderGrouped([finding], [])
    expect(output).not.toContain('[2J')  // ED — clear screen
    expect(output).not.toContain('[H')   // CUP — cursor home
    expect(output).not.toContain(']0;')  // OSC — set window title
    expect(output).not.toContain('')     // BEL
  })

  it('strips terminal control sequences from warning messages', () => {
    const output = renderGrouped([], [incomplete('pkg[2J spoof')])
    expect(output).not.toContain('[2J')
  })
})

// ── renderJson ────────────────────────────────────────────────────────────────

describe('renderJson', () => {
  // ── D8: schemaVersion ────────────────────────────────────────────────────

  it('includes schemaVersion: "1" as the first key', () => {
    const out = JSON.parse(renderJson([], []))
    expect(out.schemaVersion).toBe('1')
    expect(Object.keys(out)[0]).toBe('schemaVersion')
  })

  it('returns wrapper with empty findings and warnings when nothing provided', () => {
    const out = JSON.parse(renderJson([], []))
    expect(out).toEqual({ schemaVersion: '1', findings: [], warnings: [], warningDetails: [] })
  })

  // ── #44: warningDetails — additive field carrying ScanWarning.class ────────

  it('warningDetails carries class alongside the existing warnings: string[] (#44)', () => {
    const out = JSON.parse(
      renderJson([], [incomplete('lockfile v1 not supported'), informational('npm alias detected')]),
    )
    expect(out.warnings).toEqual(['lockfile v1 not supported', 'npm alias detected'])
    expect(out.warningDetails).toEqual([
      { class: 'incomplete', message: 'lockfile v1 not supported' },
      { class: 'informational', message: 'npm alias detected' },
    ])
  })

  it('includes name, version, advisory, and fix field in each entry', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ introduced: '0', fixed: '1.0.0' }] }),
    })
    const out = JSON.parse(renderJson([finding], []))
    expect(out.findings[0]).toMatchObject({ name: 'pkg', version: '0.9.0', fix: '1.0.0' })
    expect(out.findings[0]).toHaveProperty('advisory')
    expect(out.warnings).toEqual([])
  })

  it('includes via field only when defined', () => {
    const withVia = mkFinding({ via: 'dd-trace' })
    const withoutVia = mkFinding()
    const out = JSON.parse(renderJson([withVia, withoutVia], []))
    expect(out.findings[0]).toHaveProperty('via', 'dd-trace')
    expect(out.findings[1]).not.toHaveProperty('via')
  })

  it('fix field is absent when advisory only has inclusive upper bound (<= X)', () => {
    const finding = mkFinding({
      advisory: mkAdvisory({ ranges: [{ rawRange: '<= 0.24.2' }] }),
    })
    const out = JSON.parse(renderJson([finding], []))
    expect(out.findings[0].fix).toBeUndefined()
  })

  it('surfaces warnings in the wrapper alongside findings', () => {
    const out = JSON.parse(
      renderJson([mkFinding()], [incomplete('lockfile v1 not supported'), incomplete('git-sourced dep skipped')]),
    )
    expect(out.findings).toHaveLength(1)
    expect(out.warnings).toEqual(['lockfile v1 not supported', 'git-sourced dep skipped'])
  })
})
