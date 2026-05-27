import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { openDb, upsertAdvisory, setLastSyncedAt } from './local-db.js'

const PROJECT_ROOT = '/home/win/Yolo/Build/security-scan-cli'
const CLI_PATH = join(PROJECT_ROOT, 'src/cli.ts')
const TSX_BIN = join(PROJECT_ROOT, 'node_modules/.bin/tsx')

function spawnCli(args: string[], dbPath: string, opts: { cwd?: string } = {}) {
  return spawnSync(
    TSX_BIN,
    [CLI_PATH, ...args],
    {
      cwd: opts.cwd ?? PROJECT_ROOT,
      env: { ...process.env, VULNSCAN_DB_PATH: dbPath },
      encoding: 'utf8',
    },
  )
}

let tmpDir: string
let dbPath: string

const vulnerableLockfile = JSON.stringify({
  name: 'test-project',
  lockfileVersion: 2,
  packages: {
    '': { dependencies: { lodash: '^4.17.20' } },
    'node_modules/lodash': {
      version: '4.17.20',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
    },
  },
})

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-e2e-'))
  dbPath = join(tmpDir, 'test.sqlite')
  writeFileSync(join(tmpDir, 'package-lock.json'), vulnerableLockfile)

  // Seed DB with a known advisory for lodash@4.17.20
  const db = openDb(dbPath)
  upsertAdvisory(db, {
    id: 'CVE-2021-23337',
    canonicalId: 'GHSA-35JH-R3H4-6JHM',
    type: 'cve',
    packageName: 'lodash',
    ranges: [{ introduced: '0', fixed: '4.17.21' }],
    severity: 'high',
    title: 'Prototype Pollution',
    url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
  })
  // Mark DB as fresh so no network sync is attempted
  setLastSyncedAt(db, 'osv', Date.now())
  setLastSyncedAt(db, 'github', Date.now())
  db.close()
})

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

describe('vulnscan scan (e2e)', () => {
  it('exits 1 when findings meet the fail-on threshold', () => {
    const result = spawnSync(
      'node',
      ['--import', 'tsx', 'src/cli.ts', 'scan', tmpDir, '--fail-on', 'high,critical'],
      {
        cwd: '/home/win/Yolo/Build/security-scan-cli',
        env: { ...process.env, VULNSCAN_DB_PATH: dbPath },
        encoding: 'utf8',
      },
    )

    expect(result.status).toBe(1)
    expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
  })

  it('exits 0 when findings are below the fail-on threshold', () => {
    const result = spawnSync(
      'node',
      ['--import', 'tsx', 'src/cli.ts', 'scan', tmpDir, '--fail-on', 'critical'],
      {
        cwd: '/home/win/Yolo/Build/security-scan-cli',
        env: { ...process.env, VULNSCAN_DB_PATH: dbPath },
        encoding: 'utf8',
      },
    )

    // high severity finding, but threshold is critical-only → exit 0
    expect(result.status).toBe(0)
  })

  it('outputs JSON when --format json is passed', () => {
    const result = spawnSync(
      'node',
      ['--import', 'tsx', 'src/cli.ts', 'scan', tmpDir, '--format', 'json'],
      {
        cwd: '/home/win/Yolo/Build/security-scan-cli',
        env: { ...process.env, VULNSCAN_DB_PATH: dbPath },
        encoding: 'utf8',
      },
    )

    const parsed = JSON.parse(result.stdout)
    expect(Array.isArray(parsed.findings)).toBe(true)
    expect(Array.isArray(parsed.warnings)).toBe(true)
    expect(parsed.findings[0]).toMatchObject({ name: 'lodash', version: '4.17.20' })
  })
})

// ── Slice 1: Clean project ────────────────────────────────────────────────────

describe('vulnscan scan — clean project (no findings)', () => {
  let cleanDir: string
  let cleanDbPath: string

  beforeAll(() => {
    cleanDir = mkdtempSync(join(tmpdir(), 'vulnscan-clean-'))
    cleanDbPath = join(cleanDir, 'clean.sqlite')

    writeFileSync(join(cleanDir, 'package-lock.json'), JSON.stringify({
      name: 'clean-project',
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { 'some-safe-pkg': '1.0.0' } },
        'node_modules/some-safe-pkg': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/some-safe-pkg/-/some-safe-pkg-1.0.0.tgz',
        },
      },
    }))

    const db = openDb(cleanDbPath)
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(cleanDir, { recursive: true, force: true }))

  it('exits 0 when no vulnerabilities found', () => {
    const result = spawnCli(['scan', cleanDir], cleanDbPath)
    expect(result.status).toBe(0)
  })

  it('reports "No findings" in output', () => {
    const result = spawnCli(['scan', cleanDir], cleanDbPath)
    expect(result.stdout + result.stderr).toMatch(/no findings/i)
  })
})

// ── Slice 2: Missing package-lock.json ───────────────────────────────────────

describe('vulnscan scan — missing package-lock.json', () => {
  let emptyDir: string
  let emptyDbPath: string

  beforeAll(() => {
    emptyDir = mkdtempSync(join(tmpdir(), 'vulnscan-empty-'))
    emptyDbPath = join(emptyDir, 'empty.sqlite')
    const db = openDb(emptyDbPath)
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(emptyDir, { recursive: true, force: true }))

  it('exits 1 with error message when package-lock.json is absent', () => {
    const result = spawnCli(['scan', emptyDir], emptyDbPath)
    expect(result.status).toBe(1)
    expect(result.stderr).toMatch(/package-lock\.json not found/)
  })
})

// ── Slice 3: check command ────────────────────────────────────────────────────

describe('vulnscan check command', () => {
  it('exits 1 and shows CVE when vulnerable package is checked', () => {
    const result = spawnCli(['check', 'lodash@4.17.20'], dbPath)
    expect(result.status).toBe(1)
    expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
  })

  it('exits 0 and reports "No findings" for a safe package', () => {
    const result = spawnCli(['check', 'some-safe-pkg@1.0.0'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout + result.stderr).toMatch(/no findings/i)
  })

  it('exits 1 with usage message when no package argument given', () => {
    const result = spawnCli(['check'], dbPath)
    expect(result.status).toBe(1)
    expect(result.stderr).toMatch(/Usage: vulnscan check <package@version>/)
    expect(result.stderr).not.toMatch(/Unknown command/)
  })
})

// ── Slice 3b: check command summary line ─────────────────────────────────────

describe('vulnscan check — summary line', () => {
  it('writes "Checked pkg@ver against N advisories" to stderr in table mode', () => {
    const result = spawnCli(['check', 'lodash@4.17.20'], dbPath)
    expect(result.stderr).toMatch(/Checked lodash@4\.17\.20 against \d+ advisories/)
  })

  it('does not write summary line to stderr in --format json mode', () => {
    const result = spawnCli(['check', 'lodash@4.17.20', '--format', 'json'], dbPath)
    expect(result.stderr).not.toMatch(/Checked lodash/)
  })

  it('stdout is clean JSON in --format json mode', () => {
    const result = spawnCli(['check', 'lodash@4.17.20', '--format', 'json'], dbPath)
    expect(() => JSON.parse(result.stdout)).not.toThrow()
  })
})

// ── Slice 4: Warnings in output ───────────────────────────────────────────────

describe('vulnscan scan — warnings', () => {
  let warnDir: string
  let warnDbPath: string

  beforeAll(() => {
    warnDir = mkdtempSync(join(tmpdir(), 'vulnscan-warn-'))
    warnDbPath = join(warnDir, 'warn.sqlite')

    writeFileSync(join(warnDir, 'package-lock.json'), JSON.stringify({
      name: 'warn-project',
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { 'git-dep': 'git+https://github.com/example/dep.git' } },
        'node_modules/git-dep': {
          version: '1.0.0',
          resolved: 'git+https://github.com/example/dep.git',
        },
      },
    }))

    const db = openDb(warnDbPath)
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(warnDir, { recursive: true, force: true }))

  it('includes warning in output when lockfile has a git-sourced dependency', () => {
    const result = spawnCli(['scan', warnDir], warnDbPath)
    expect(result.stdout + result.stderr).toMatch(/git-sourced dep skipped/)
  })
})

// ── Slice 5: .vulnscanrc config file ─────────────────────────────────────────

describe('vulnscan scan — .vulnscanrc config', () => {
  let configDir: string
  let configDbPath: string

  beforeAll(() => {
    configDir = mkdtempSync(join(tmpdir(), 'vulnscan-config-'))
    configDbPath = join(configDir, 'config.sqlite')

    writeFileSync(join(configDir, 'package-lock.json'), JSON.stringify({
      name: 'config-project',
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { somelib: '^1.0.0' } },
        'node_modules/somelib': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/somelib/-/somelib-1.0.0.tgz',
        },
      },
    }))

    const db = openDb(configDbPath)
    upsertAdvisory(db, {
      id: 'CVE-2024-MODERATE',
      canonicalId: 'CVE-2024-MODERATE',
      type: 'cve',
      packageName: 'somelib',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
      severity: 'moderate',
      title: 'Moderate issue',
      url: 'https://example.com',
    })
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(configDir, { recursive: true, force: true }))

  it('exits 0 for moderate finding without .vulnscanrc (default failOn is critical,high)', () => {
    const result = spawnCli(['scan', configDir], configDbPath)
    expect(result.status).toBe(0)
  })

  it('exits 1 for moderate finding when .vulnscanrc sets failOn to moderate', () => {
    writeFileSync(join(configDir, '.vulnscanrc'), JSON.stringify({ failOn: ['moderate'] }))
    const result = spawnCli(['scan', configDir], configDbPath)
    rmSync(join(configDir, '.vulnscanrc'))
    expect(result.status).toBe(1)
  })
})

// ── Slice 6: Monorepo workspace lockfile ─────────────────────────────────────

describe('vulnscan scan — monorepo workspace lockfile', () => {
  let monoDir: string
  let monoDbPath: string

  beforeAll(() => {
    monoDir = mkdtempSync(join(tmpdir(), 'vulnscan-mono-'))
    monoDbPath = join(monoDir, 'mono.sqlite')

    writeFileSync(join(monoDir, 'package-lock.json'), JSON.stringify({
      name: 'monorepo',
      lockfileVersion: 2,
      packages: {
        '': { workspaces: ['packages/*'] },
        'packages/frontend': { version: '1.0.0' },
        'node_modules/lodash': {
          version: '4.17.20',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
        },
      },
    }))

    const db = openDb(monoDbPath)
    upsertAdvisory(db, {
      id: 'CVE-2021-23337',
      canonicalId: 'GHSA-35JH-R3H4-6JHM',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Prototype Pollution',
      url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
    })
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(monoDir, { recursive: true, force: true }))

  it('detects vulnerabilities in node_modules entries and ignores workspace path entries', () => {
    const result = spawnCli(['scan', monoDir, '--fail-on', 'high'], monoDbPath)
    expect(result.status).toBe(1)
    expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
    expect(result.stdout + result.stderr).not.toMatch(/packages\/frontend/)
  })
})

// ── Slice 7: No path argument defaults to current directory ───────────────────

describe('vulnscan scan — no path argument', () => {
  it('scans current directory when no path argument given', () => {
    // cwd=tmpDir so "." resolves to tmpDir (which has the vulnerable lodash lockfile)
    const result = spawnCli(['scan'], dbPath, { cwd: tmpDir })
    expect(result.status).toBe(1)
    expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
  })
})

// ── Slice 8: Unknown command ──────────────────────────────────────────────────

describe('vulnscan — unknown command', () => {
  it('exits 1 with usage message for unrecognised command', () => {
    const result = spawnCli(['foobar'], dbPath)
    expect(result.status).toBe(1)
    expect(result.stderr).toMatch(/Unknown command/)
  })
})

// ── Slice 9: Unknown command does not create DB ───────────────────────────────

describe('vulnscan — unknown command does not create DB', () => {
  it('does not create the DB file when command is unrecognised', () => {
    const isolatedDir = mkdtempSync(join(tmpdir(), 'vulnscan-nodb-'))
    const isolatedDbPath = join(isolatedDir, 'shouldnotexist.db')
    try {
      const result = spawnCli(['unknowncmd'], isolatedDbPath)
      expect(result.status).toBe(1)
      expect(result.stderr).toMatch(/Unknown command/)
      expect(existsSync(isolatedDbPath)).toBe(false)
    } finally {
      rmSync(isolatedDir, { recursive: true, force: true })
    }
  })
})

// ── Slice 10 (B2): DB handle released on error ───────────────────────────────
// Run two back-to-back CLI calls against the same DB path where the first
// call ends (even via an error path). The second call must succeed without
// any SQLITE_BUSY / locked-database error, proving the handle was closed.

describe('vulnscan — db handle released after scan', () => {
  it('second scan against same DB succeeds after first scan exits', () => {
    // First call — normal scan (exits 1 because high finding meets threshold)
    const first = spawnCli(['scan', tmpDir, '--fail-on', 'high'], dbPath)
    expect(first.status).toBe(1)

    // Second call — must not receive SQLITE_BUSY or fail due to leftover handle
    const second = spawnCli(['scan', tmpDir, '--fail-on', 'high'], dbPath)
    expect(second.stderr).not.toMatch(/SQLITE_BUSY|locked|unable to open/)
    expect(second.status).toBe(1)
  })
})

// ── Slice 11 (M1): JSON output must not be truncated ─────────────────────────
// Seed a DB with many advisories, run scan --format json, verify JSON.parse
// succeeds (truncation from premature process.exit would cause a SyntaxError).

describe('vulnscan scan — json output completeness', () => {
  let bigDir: string
  let bigDbPath: string

  beforeAll(() => {
    bigDir = mkdtempSync(join(tmpdir(), 'vulnscan-big-'))
    bigDbPath = join(bigDir, 'big.sqlite')

    // Build a lockfile with many vulnerable packages
    const packages: Record<string, { version: string; resolved: string }> = {}
    const deps: Record<string, string> = {}
    for (let i = 0; i < 50; i++) {
      const name = `vuln-pkg-${i}`
      deps[name] = '^1.0.0'
      packages[`node_modules/${name}`] = {
        version: '1.0.0',
        resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
      }
    }
    writeFileSync(join(bigDir, 'package-lock.json'), JSON.stringify({
      name: 'big-project',
      lockfileVersion: 2,
      packages: { '': { dependencies: deps }, ...packages },
    }))

    const db = openDb(bigDbPath)
    for (let i = 0; i < 50; i++) {
      upsertAdvisory(db, {
        id: `CVE-2024-BIG-${i}`,
        canonicalId: `CVE-2024-BIG-${i}`,
        type: 'cve',
        packageName: `vuln-pkg-${i}`,
        ranges: [{ introduced: '0', fixed: '2.0.0' }],
        severity: 'high',
        title: `Big finding ${i}`,
        url: `https://example.com/${i}`,
      })
    }
    setLastSyncedAt(db, 'osv', Date.now())
    setLastSyncedAt(db, 'github', Date.now())
    db.close()
  })

  afterAll(() => rmSync(bigDir, { recursive: true, force: true }))

  it('JSON.parse succeeds on --format json output with many findings', () => {
    const result = spawnCli(['scan', bigDir, '--format', 'json'], bigDbPath)
    // Must parse without throwing — truncation would cause SyntaxError
    expect(() => JSON.parse(result.stdout)).not.toThrow()
    const parsed = JSON.parse(result.stdout)
    expect(Array.isArray(parsed.findings)).toBe(true)
    expect(parsed.findings.length).toBe(50)
  })
})

// ── Slice 12 (M2): --fail-on typo warns and still gates valid severities ──────

describe('vulnscan scan — --fail-on typo handling', () => {
  it('warns about invalid severity token and still exits 1 for valid matching token', () => {
    // 'critica' is a typo; 'high' is valid and matches the seeded advisory
    const result = spawnCli(['scan', tmpDir, '--fail-on', 'critica,high'], dbPath)
    expect(result.stderr).toMatch(/critica/)
    expect(result.status).toBe(1)
  })

  it('falls back to defaults when ALL tokens are invalid', () => {
    // No valid severity → fall back to default [critical, high]; seeded advisory is high → exit 1
    const result = spawnCli(['scan', tmpDir, '--fail-on', 'typo1,typo2'], dbPath)
    expect(result.stderr).toMatch(/typo1/)
    expect(result.stderr).toMatch(/typo2/)
    // default fallback includes high, seeded advisory is high → exit 1
    expect(result.status).toBe(1)
  })
})

// ── Slice 14 (N1): --help prints usage to stdout, exits 0 ────────────────────

describe('vulnscan --help', () => {
  it('exits 0 and writes usage to stdout', () => {
    const result = spawnCli(['--help'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/Usage:/)
    expect(result.stdout).toMatch(/--help/)
    expect(result.stderr).toBe('')
  })

  it('-h is equivalent to --help', () => {
    const result = spawnCli(['-h'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/Usage:/)
  })

  it('scan --help shows scan-specific usage', () => {
    const result = spawnCli(['scan', '--help'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/vulnscan scan/)
    expect(result.stdout).not.toMatch(/<pkg@version>/)
  })

  it('check --help shows check-specific usage', () => {
    const result = spawnCli(['check', '--help'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/vulnscan check/)
    expect(result.stdout).toMatch(/<pkg@version>/)
  })

  it('update --help shows update-specific usage', () => {
    const result = spawnCli(['update', '--help'], dbPath)
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/vulnscan update/)
    expect(result.stdout).toMatch(/VULNSCAN_DB_PATH/)
  })
})

// ── Skill consumer: JSON output contract ─────────────────────────────────────
// These tests pin the JSON shape the /vulnscan Claude Code Skill depends on.
// Each cycle maps to an acceptance criterion in .claude/issues/12a-skill-scaffold.md
// and .claude/issues/12b-signal-enrichment.md.

describe('vulnscan scan — JSON output contract (skill consumer)', () => {
  // Cycle 1: full advisory fields + fix present
  it('finding includes advisory sub-fields and fix version', () => {
    const result = spawnCli(['scan', tmpDir, '--format', 'json'], dbPath)
    const parsed = JSON.parse(result.stdout)
    const finding = parsed.findings[0]

    expect(finding).toMatchObject({ name: 'lodash', version: '4.17.20' })
    expect(finding.advisory).toMatchObject({
      id: 'CVE-2021-23337',
      type: 'cve',
      severity: 'high',
      title: expect.any(String),
      url: expect.any(String),
    })
    expect(finding.fix).toBe('4.17.21')
  })

  // Cycle 2: fix is undefined when advisory has no fixed range
  it('fix is undefined when advisory has no fixed range', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-nofix-'))
    const dbp = join(dir, 'nofix.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'nofix-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'no-fix-pkg': '^1.0.0' } },
          'node_modules/no-fix-pkg': { version: '1.0.0', resolved: 'https://registry.npmjs.org/no-fix-pkg/-/no-fix-pkg-1.0.0.tgz' },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'CVE-2024-NOFIX', canonicalId: 'CVE-2024-NOFIX', type: 'cve',
        packageName: 'no-fix-pkg', ranges: [{ introduced: '0' }],
        severity: 'high', title: 'No fix advisory', url: 'https://example.com/nofix',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--format', 'json'], dbp)
      const parsed = JSON.parse(result.stdout)
      expect(parsed.findings[0].fix).toBeUndefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // Cycle 3: advisory.type === 'mal' for malicious package
  it('advisory.type is "mal" for malicious package advisory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-mal-'))
    const dbp = join(dir, 'mal.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'mal-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'evil-pkg': '^1.0.0' } },
          'node_modules/evil-pkg': { version: '1.0.0', resolved: 'https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz' },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'MAL-2024-1234', canonicalId: 'MAL-2024-1234', type: 'mal',
        packageName: 'evil-pkg', ranges: [{ introduced: '0' }],
        severity: 'critical', title: 'Malicious package: data exfiltration',
        url: 'https://osv.dev/vulnerability/MAL-2024-1234',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--format', 'json'], dbp)
      const parsed = JSON.parse(result.stdout)
      expect(parsed.findings[0].advisory.type).toBe('mal')
      expect(parsed.findings[0].advisory.id).toBe('MAL-2024-1234')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // Cycle 4: warnings array is non-empty in JSON format for git-sourced deps
  it('warnings array is non-empty in JSON output for git-sourced dependencies', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-warnj-'))
    const dbp = join(dir, 'warnj.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'warn-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'git-dep': 'git+https://github.com/example/dep.git' } },
          'node_modules/git-dep': { version: '1.0.0', resolved: 'git+https://github.com/example/dep.git' },
        },
      }))
      const db = openDb(dbp)
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--format', 'json'], dbp)
      const parsed = JSON.parse(result.stdout)
      expect(Array.isArray(parsed.warnings)).toBe(true)
      expect(parsed.warnings.length).toBeGreaterThan(0)
      expect(parsed.warnings[0]).toMatch(/git-sourced dep skipped/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

// ── Slice 13 (M4): check command threads stalenessHours ──────────────────────
// Verify that check with a .vulnscanrc stalenessHours=0 still works correctly
// (forces sync to appear stale, but since we seed last_sync_at=now the DB is fresh).
// This is a behavioral smoke test; the unit-level assertion is in config.ts tests.

describe('vulnscan check — stalenessHours respected', () => {
  it('check command completes without error when .vulnscanrc sets stalenessHours', () => {
    // Write a .vulnscanrc in tmpDir with a large stalenessHours (DB is fresh, no sync needed)
    const rcPath = join(tmpDir, '.vulnscanrc')
    writeFileSync(rcPath, JSON.stringify({ stalenessHours: 999, failOn: ['high'] }))
    try {
      const result = spawnCli(['check', 'lodash@4.17.20'], dbPath, { cwd: tmpDir })
      // Should find the advisory and exit 1 (high finding, failOn includes high)
      expect(result.status).toBe(1)
      expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
    } finally {
      rmSync(rcPath, { force: true })
    }
  })

  it('F1: check --dir threads through to failOn config, not just stalenessHours', () => {
    // Create a SECOND tmp dir with .vulnscanrc that excludes 'high' from failOn.
    // If --dir is correctly threaded, the high finding will NOT trip exit 1.
    // If --dir is ignored for failOn (the F1 bug), the CWD's .vulnscanrc (or defaults) takes over,
    // which by default includes 'high' → exit 1.
    const otherDir = mkdtempSync(join(tmpdir(), 'vulnscan-other-'))
    try {
      writeFileSync(
        join(otherDir, '.vulnscanrc'),
        JSON.stringify({ stalenessHours: 999, failOn: ['critical'] }),
      )
      // Run from PROJECT_ROOT so CWD's .vulnscanrc (if any) is unrelated; --dir points at otherDir
      const result = spawnCli(['check', 'lodash@4.17.20', '--dir', otherDir], dbPath)
      // failOn=['critical'] — the finding is severity 'high', so it must NOT trip exit 1.
      expect(result.status).toBe(0)
      expect(result.stdout + result.stderr).toMatch(/CVE-2021-23337/)
    } finally {
      rmSync(otherDir, { recursive: true, force: true })
    }
  })
})

// ── D7: workspace local:true — workspace pkg not advisory-checked ─────────────

describe('vulnscan scan — D7 workspace local dep not scanned against advisories', () => {
  it('workspace package (link:true) with matching advisory name does not produce a finding', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-ws-local-'))
    const dbp = join(dir, 'ws-local.sqlite')
    try {
      // Lockfile with a workspace entry via link:true named "lodash" (same as an advisory package)
      // If local:true skipping works, no finding should be returned despite advisory existing.
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'monorepo', lockfileVersion: 2,
        packages: {
          '': {},
          'packages/lodash': { version: '1.0.0', name: 'lodash', link: true },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'CVE-TEST-WS01',
        canonicalId: 'GHSA-0000-0000-WS01',
        type: 'cve',
        packageName: 'lodash',
        ranges: [{ introduced: '0', fixed: '2.0.0' }],
        severity: 'critical',
        title: 'Test advisory for lodash',
        url: 'https://github.com/advisories/GHSA-0000-0000-WS01',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--format', 'json'], dbp)
      const parsed = JSON.parse(result.stdout)
      // Workspace dep is local:true — advisory store lookup must be skipped → no findings
      expect(parsed.findings).toHaveLength(0)
      expect(result.status).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

// ── D7: npm alias — advisory for target package is matched ───────────────────

describe('vulnscan scan — D7 npm alias resolves advisories against target package', () => {
  it('alias dep triggers finding when advisory exists for the aliased target package', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-alias-'))
    const dbp = join(dir, 'alias.sqlite')
    try {
      // lodash-fork is an alias for lodash@4.17.20 — advisory covers lodash < 4.17.21
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'my-app', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'lodash-fork': 'npm:lodash@4.17.20' } },
          'node_modules/lodash-fork': {
            version: '4.17.20',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
            name: 'lodash',
          },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'CVE-2021-23337',
        canonicalId: 'GHSA-35JH-R3H4-6JHM',
        type: 'cve',
        packageName: 'lodash',
        ranges: [{ introduced: '0', fixed: '4.17.21' }],
        severity: 'high',
        title: 'Prototype Pollution',
        url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--format', 'json'], dbp)
      const parsed = JSON.parse(result.stdout)
      // The alias dep (lodash-fork → lodash@4.17.20) must surface as a finding for lodash
      expect(parsed.findings.length).toBeGreaterThan(0)
      expect(parsed.findings[0].name).toBe('lodash')
      expect(result.status).toBe(1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

// ── D5T: --offline flag ───────────────────────────────────────────────────────

describe('vulnscan scan — --offline flag (empty DB, never synced)', () => {
  it('exits 0 and emits informational warning when DB has never been synced', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-offline-empty-'))
    const dbp = join(dir, 'offline-empty.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'test-project', lockfileVersion: 2,
        packages: { '': {}, 'node_modules/some-pkg-no-advisory': { version: '1.0.0', resolved: 'https://registry.npmjs.org/some-pkg-no-advisory/-/some-pkg-no-advisory-1.0.0.tgz' } },
      }))
      // Create empty DB (no advisory data, no sync cursors) to prevent bootstrap
      const db = openDb(dbp)
      db.close()

      const result = spawnCli(['scan', dir, '--offline', '--format', 'json'], dbp)
      expect(result.status).toBe(0)
      const parsed = JSON.parse(result.stdout)
      expect(parsed.findings).toHaveLength(0)
      expect(Array.isArray(parsed.warnings)).toBe(true)
      // JSON warnings are serialized as message strings (see renderJson)
      expect(parsed.warnings.length).toBeGreaterThan(0)
      expect(parsed.warnings.some((w: string) => w.includes('never been synced'))).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('--no-sync alias: exits 0 and emits informational warning when DB has never been synced', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-no-sync-'))
    const dbp = join(dir, 'no-sync.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'test-project', lockfileVersion: 2,
        packages: { '': {} },
      }))
      // Create empty DB to prevent bootstrap
      const db = openDb(dbp)
      db.close()

      const result = spawnCli(['scan', dir, '--no-sync', '--format', 'json'], dbp)
      expect(result.status).toBe(0)
      const parsed = JSON.parse(result.stdout)
      expect(Array.isArray(parsed.warnings)).toBe(true)
      // JSON warnings are serialized as message strings (see renderJson)
      expect(parsed.warnings.length).toBeGreaterThan(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('vulnscan scan — --offline flag (stale DB, cursor > 7 days)', () => {
  it('exits 0 and emits informational warning when DB cursors are older than 7 days', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-offline-stale-'))
    const dbp = join(dir, 'offline-stale.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'test-project', lockfileVersion: 2,
        packages: { '': {}, 'node_modules/some-pkg-no-advisory': { version: '1.0.0', resolved: 'https://registry.npmjs.org/some-pkg-no-advisory/-/some-pkg-no-advisory-1.0.0.tgz' } },
      }))
      // Seed DB with backdate cursors to 8 days ago (no advisory data)
      const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000
      const db = openDb(dbp)
      setLastSyncedAt(db, 'osv', eightDaysAgo)
      setLastSyncedAt(db, 'github', eightDaysAgo)
      db.close()

      const result = spawnCli(['scan', dir, '--offline', '--format', 'json'], dbp)
      expect(result.status).toBe(0)
      const parsed = JSON.parse(result.stdout)
      expect(Array.isArray(parsed.warnings)).toBe(true)
      // JSON warnings are serialized as message strings (see renderJson)
      expect(parsed.warnings.length).toBeGreaterThan(0)
      // Should mention stale data
      expect(parsed.warnings.some((w: string) => w.includes('stale'))).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

// ── D1: Exit code matrix (0/1/2) ─────────────────────────────────────────────

describe('vulnscan scan — D1 exit code matrix', () => {
  // Cell: clean (exit 0)
  it('exits 0 when no findings and no incomplete warnings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-d1-clean-'))
    const dbp = join(dir, 'clean.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'clean-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'safe-pkg': '^1.0.0' } },
          'node_modules/safe-pkg': { version: '1.0.0', resolved: 'https://registry.npmjs.org/safe-pkg/-/safe-pkg-1.0.0.tgz' },
        },
      }))
      const db = openDb(dbp)
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir], dbp)
      expect(result.status).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // Cell: findings (exit 1)
  it('exits 1 when findings meet fail-on threshold', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-d1-findings-'))
    const dbp = join(dir, 'findings.sqlite')
    try {
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'vuln-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { lodash: '^4.17.20' } },
          'node_modules/lodash': { version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'CVE-2021-23337', canonicalId: 'GHSA-35JH-R3H4-6JHM', type: 'cve',
        packageName: 'lodash', ranges: [{ introduced: '0', fixed: '4.17.21' }],
        severity: 'high', title: 'Prototype Pollution', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir, '--fail-on', 'high'], dbp)
      expect(result.status).toBe(1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // Cell: incomplete-only (exit 2) — git-sourced dep triggers class:'incomplete', no findings
  it('exits 2 when scan has incomplete warning and no qualifying findings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-d1-incomplete-'))
    const dbp = join(dir, 'incomplete.sqlite')
    try {
      // git-sourced dep → lockfile-resolver emits class:'incomplete' warning
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'git-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { 'git-dep': 'git+https://github.com/example/dep.git' } },
          'node_modules/git-dep': { version: '1.0.0', resolved: 'git+https://github.com/example/dep.git' },
        },
      }))
      const db = openDb(dbp)
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      const result = spawnCli(['scan', dir], dbp)
      expect(result.status).toBe(2)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // Cell: findings + incomplete (exit 1, findings override)
  it('exits 1 when findings exist even alongside incomplete warnings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vulnscan-d1-both-'))
    const dbp = join(dir, 'both.sqlite')
    try {
      // Mix: one registry dep with a vuln + one git-sourced dep (incomplete)
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'mixed-project', lockfileVersion: 2,
        packages: {
          '': { dependencies: { lodash: '^4.17.20', 'git-dep': 'git+https://github.com/example/dep.git' } },
          'node_modules/lodash': { version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' },
          'node_modules/git-dep': { version: '1.0.0', resolved: 'git+https://github.com/example/dep.git' },
        },
      }))
      const db = openDb(dbp)
      upsertAdvisory(db, {
        id: 'CVE-2021-23337', canonicalId: 'GHSA-35JH-R3H4-6JHM', type: 'cve',
        packageName: 'lodash', ranges: [{ introduced: '0', fixed: '4.17.21' }],
        severity: 'high', title: 'Prototype Pollution', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
      })
      setLastSyncedAt(db, 'osv', Date.now())
      setLastSyncedAt(db, 'github', Date.now())
      db.close()

      // findings (high) + incomplete (git-dep) → exit 1 (findings override)
      const result = spawnCli(['scan', dir, '--fail-on', 'high'], dbp)
      expect(result.status).toBe(1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('vulnscan check — D1 exit code matrix', () => {
  // Cell: clean (exit 0)
  it('exits 0 when no findings and no incomplete warnings', () => {
    const result = spawnCli(['check', 'some-safe-pkg@1.0.0'], dbPath)
    expect(result.status).toBe(0)
  })

  // Cell: findings (exit 1)
  it('exits 1 when findings meet fail-on threshold', () => {
    const result = spawnCli(['check', 'lodash@4.17.20', '--fail-on', 'high'], dbPath)
    expect(result.status).toBe(1)
  })

  // Cell: findings + incomplete → exit 1 (findings override)
  it('exits 1 when findings exist, confirming findings override incomplete warnings', () => {
    // The seeded DB has a high advisory for lodash. Findings take priority over any warnings.
    const result = spawnCli(['check', 'lodash@4.17.20', '--fail-on', 'high'], dbPath)
    expect(result.status).toBe(1)
  })
})

describe('vulnscan --help — D1 exit codes documented', () => {
  it('global --help lists exit codes 0, 1, and 2', () => {
    const result = spawnCli(['--help'], dbPath)
    expect(result.stdout).toMatch(/exit code/i)
    expect(result.stdout).toMatch(/\b0\b/)
    expect(result.stdout).toMatch(/\b1\b/)
    expect(result.stdout).toMatch(/\b2\b/)
  })

  it('scan --help lists exit codes 0, 1, and 2', () => {
    const result = spawnCli(['scan', '--help'], dbPath)
    expect(result.stdout).toMatch(/exit code/i)
    expect(result.stdout).toMatch(/\b0\b/)
    expect(result.stdout).toMatch(/\b1\b/)
    expect(result.stdout).toMatch(/\b2\b/)
  })

  it('check --help lists exit codes 0, 1, and 2', () => {
    const result = spawnCli(['check', '--help'], dbPath)
    expect(result.stdout).toMatch(/exit code/i)
    expect(result.stdout).toMatch(/\b0\b/)
    expect(result.stdout).toMatch(/\b1\b/)
    expect(result.stdout).toMatch(/\b2\b/)
  })
})
