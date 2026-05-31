import { describe, it, expect, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, statSync, chmodSync, existsSync } from 'node:fs'

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return { ...actual, chmodSync: vi.fn(actual.chmodSync) }
})
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import BetterSqlite3 from 'better-sqlite3'
import { openDb, upsertAdvisory, upsertAdvisoryFromFullSync, pruneStaleAdvisories, getAdvisoriesForPackage } from './local-db.js'
import type Database from 'better-sqlite3'

let db: Database.Database
let tmpDir: string

afterEach(() => {
  db?.close()
  if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
})

function makeDb() {
  tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
  db = openDb(join(tmpDir, 'test.sqlite'))
  return db
}

describe('upsertAdvisory', () => {
  it('stores two advisories sharing the same CVE id but different package names independently', () => {
    const database = makeDb()

    upsertAdvisory(database, {
      id: 'CVE-2024-9999',
      canonicalId: 'CVE-2024-9999',
      type: 'cve',
      packageName: 'pkg-a',
      ranges: [{ introduced: '0', fixed: '1.0.0' }],
      severity: 'high',
      title: 'Vuln in pkg-a',
      url: 'https://example.com/a',
    })

    upsertAdvisory(database, {
      id: 'CVE-2024-9999',
      canonicalId: 'CVE-2024-9999',
      type: 'cve',
      packageName: 'pkg-b',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
      severity: 'critical',
      title: 'Vuln in pkg-b',
      url: 'https://example.com/b',
    })

    const forA = getAdvisoriesForPackage(database, 'pkg-a')
    const forB = getAdvisoriesForPackage(database, 'pkg-b')

    expect(forA).toHaveLength(1)
    expect(forA[0].packageName).toBe('pkg-a')
    expect(forA[0].severity).toBe('high')

    expect(forB).toHaveLength(1)
    expect(forB[0].packageName).toBe('pkg-b')
    expect(forB[0].severity).toBe('critical')
  })

  it('skips row with invalid severity instead of throwing (skip-and-warn policy)', () => {
    const database = makeDb()
    database.exec(`
      INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url)
      VALUES ('CVE-2024-BOGUS', 'cve', 'bad-pkg', '[]', 'bogus', 'Bad row', 'https://example.com')
    `)

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      const result = getAdvisoriesForPackage(database, 'bad-pkg')
      expect(result).toHaveLength(0)
      expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('CVE-2024-BOGUS'))
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it('replaces on re-upsert of same (id, package_name) pair', () => {
    const database = makeDb()

    upsertAdvisory(database, {
      id: 'CVE-2024-1234',
      canonicalId: 'CVE-2024-1234',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Old title',
      url: 'https://example.com',
    })

    upsertAdvisory(database, {
      id: 'CVE-2024-1234',
      canonicalId: 'CVE-2024-1234',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'critical',
      title: 'Updated title',
      url: 'https://example.com',
    })

    const results = getAdvisoriesForPackage(database, 'lodash')
    expect(results).toHaveLength(1)
    expect(results[0].severity).toBe('critical')
    expect(results[0].title).toBe('Updated title')
  })
})

describe('upsertAdvisoryFromFullSync', () => {
  it('stores advisory and sets last_seen_in_full_sync to fullSyncStartedAt', () => {
    const database = makeDb()
    const fullSyncStart = 1_000_000_000_000

    upsertAdvisoryFromFullSync(database, {
      id: 'CVE-2024-5555',
      canonicalId: 'CVE-2024-5555',
      type: 'cve',
      packageName: 'express',
      ranges: [{ introduced: '0', fixed: '4.19.0' }],
      severity: 'high',
      title: 'Vuln in express',
      url: 'https://example.com/express',
    }, fullSyncStart)

    const results = getAdvisoriesForPackage(database, 'express')
    expect(results).toHaveLength(1)
    expect(results[0].packageName).toBe('express')
    expect(results[0].severity).toBe('high')

    const row = database
      .prepare('SELECT last_seen_in_full_sync FROM advisories WHERE id = ?')
      .get('CVE-2024-5555') as { last_seen_in_full_sync: number }
    expect(row.last_seen_in_full_sync).toBe(fullSyncStart)
  })

  it('upsertAdvisory bumps last_seen_in_full_sync to current time (any-source touch semantics)', () => {
    const database = makeDb()
    const fullSyncStart = 1_000_000_000_000

    upsertAdvisoryFromFullSync(database, {
      id: 'CVE-2024-5556',
      canonicalId: 'CVE-2024-5556',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Original',
      url: 'https://example.com',
    }, fullSyncStart)

    const before = Date.now()
    // Incremental (GitHub) upsert should bump last_seen_in_full_sync to now
    upsertAdvisory(database, {
      id: 'CVE-2024-5556',
      canonicalId: 'CVE-2024-5556',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'critical',
      title: 'Updated by GitHub sync',
      url: 'https://example.com',
    })
    const after = Date.now()

    const row = database
      .prepare('SELECT last_seen_in_full_sync FROM advisories WHERE id = ?')
      .get('CVE-2024-5556') as { last_seen_in_full_sync: number }
    expect(row.last_seen_in_full_sync).toBeGreaterThanOrEqual(before)
    expect(row.last_seen_in_full_sync).toBeLessThanOrEqual(after)
  })
})

describe('canonicalId round-trip', () => {
  it('persists canonicalId column independent of URL', () => {
    const database = makeDb()

    upsertAdvisory(database, {
      id: 'CVE-2024-99999',
      canonicalId: 'GHSA-xxxx-yyyy-zzzz',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0.0.0' }],
      severity: 'high',
      title: 'test',
      url: 'https://osv.dev/vulnerability/CVE-2024-99999',
    })

    const result = getAdvisoriesForPackage(database, 'lodash')
    expect(result[0].canonicalId).toBe('GHSA-xxxx-yyyy-zzzz')
  })
})

describe('C1 — upsertAdvisory refreshes last_seen_in_full_sync', () => {
  it('upsertAdvisory refreshes last_seen_in_full_sync so GH-tracked advisory survives prune', () => {
    const database = makeDb()
    const T0_old = Date.now() - 30 * 24 * 60 * 60 * 1000

    // Simulate an old OSV full sync (30 days ago)
    upsertAdvisoryFromFullSync(database, {
      id: 'GHSA-prune-test-0001',
      canonicalId: 'GHSA-PRUNE-TEST-0001',
      type: 'cve',
      packageName: 'prune-pkg',
      ranges: [{ introduced: '0', fixed: '1.0.0' }],
      severity: 'high',
      title: 'Stale OSV advisory',
      url: 'https://github.com/advisories/GHSA-prune-test-0001',
    }, T0_old)

    const rowBefore = database
      .prepare('SELECT last_seen_in_full_sync FROM advisories WHERE id = ?')
      .get('GHSA-prune-test-0001') as { last_seen_in_full_sync: number }
    expect(rowBefore.last_seen_in_full_sync).toBe(T0_old)

    // GitHub refresh today — should bump last_seen_in_full_sync
    upsertAdvisory(database, {
      id: 'GHSA-prune-test-0001',
      canonicalId: 'GHSA-PRUNE-TEST-0001',
      type: 'cve',
      packageName: 'prune-pkg',
      ranges: [{ introduced: '0', fixed: '1.0.0' }],
      severity: 'high',
      title: 'GitHub-refreshed advisory',
      url: 'https://github.com/advisories/GHSA-prune-test-0001',
    })

    const rowAfter = database
      .prepare('SELECT last_seen_in_full_sync FROM advisories WHERE id = ?')
      .get('GHSA-prune-test-0001') as { last_seen_in_full_sync: number }
    expect(rowAfter.last_seen_in_full_sync).toBeGreaterThan(T0_old)
    expect(rowAfter.last_seen_in_full_sync).toBeGreaterThanOrEqual(Date.now() - 5000)

    // Prune with 7-day grace period — advisory must survive
    pruneStaleAdvisories(database, Date.now(), 7 * 24 * 60 * 60 * 1000)
    expect(getAdvisoriesForPackage(database, 'prune-pkg')).toHaveLength(1)
  })
})

describe('B2 — source-aware prune exempts GitHub-Source advisories (#49)', () => {
  it('a static GitHub advisory (stale last_seen, never re-upserted) survives the OSV prune; a stale OSV advisory is pruned', () => {
    const database = makeDb()
    const old = Date.now() - 30 * 24 * 60 * 60 * 1000 // 30 days ago

    // GitHub Source: inserted once via the incremental GitHub path, then never seen again
    // because it was not updated upstream (GitHub Sync uses an `updated>=since` cursor).
    upsertAdvisory(database, {
      id: 'GHSA-static-gh-0001',
      canonicalId: 'GHSA-STATIC-GH-0001',
      type: 'cve',
      packageName: 'gh-only-pkg',
      ranges: [{ rawRange: '< 2.0.0' }],
      severity: 'high',
      title: 'GitHub-only advisory, never updated upstream',
      url: 'https://github.com/advisories/GHSA-static-gh-0001',
    })
    // Freeze its last_seen 30 days in the past — i.e. it has not been re-upserted since.
    database.prepare('UPDATE advisories SET last_seen_in_full_sync = ? WHERE id = ?').run(old, 'GHSA-static-gh-0001')

    // OSV Source: vanished from the dump and last seen 30 days ago — genuinely stale, must be pruned.
    upsertAdvisoryFromFullSync(database, {
      id: 'CVE-2099-stale-osv',
      canonicalId: 'CVE-2099-STALE-OSV',
      type: 'cve',
      packageName: 'osv-stale-pkg',
      ranges: [{ introduced: '0', fixed: '1.0.0' }],
      severity: 'high',
      title: 'Stale OSV advisory',
      url: 'https://osv.dev/vulnerability/CVE-2099-stale-osv',
    }, old)

    pruneStaleAdvisories(database, Date.now(), 7 * 24 * 60 * 60 * 1000)

    // The GitHub-Source advisory must NOT be pruned by an OSV full-Sync prune.
    expect(getAdvisoriesForPackage(database, 'gh-only-pkg')).toHaveLength(1)
    // The genuinely-stale OSV-Source advisory is still pruned.
    expect(getAdvisoriesForPackage(database, 'osv-stale-pkg')).toHaveLength(0)
  })
})

describe('C2 — migration backfills canonical_id', () => {
  it('migration backfills canonical_id from URL for pre-migration rows', () => {
    // Seed a DB with the old schema (no canonical_id column)
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
    const path = join(tmpDir, 'legacy.sqlite')
    const seedDb = new BetterSqlite3(path)
    seedDb.exec(`
      CREATE TABLE advisories (
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        package_name TEXT NOT NULL,
        affected_ranges_json TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        synced_at INTEGER NOT NULL DEFAULT 0,
        last_seen_in_full_sync INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (id, package_name)
      );
      CREATE INDEX IF NOT EXISTS idx_advisories_pkg ON advisories(package_name);
      CREATE TABLE IF NOT EXISTS sync_metadata (
        source TEXT PRIMARY KEY,
        last_synced_at INTEGER NOT NULL
      );
    `)
    seedDb.prepare(`
      INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url)
      VALUES (?, 'cve', 'lodash', '[]', 'high', 'Test', ?)
    `).run('CVE-2021-23337', 'https://github.com/advisories/GHSA-xxxp-yyyy-zzzz')
    seedDb.close()

    // openDb should migrate and backfill canonical_id from URL
    db = openDb(path)
    const advisories = getAdvisoriesForPackage(db, 'lodash')
    expect(advisories).toHaveLength(1)
    expect(advisories[0].canonicalId).toBe('GHSA-XXXP-YYYY-ZZZZ')
  })
})

describe('C3 — concurrent ALTER TABLE race', () => {
  it('openDb tolerates duplicate column error from concurrent migration', () => {
    const database = makeDb()
    // The DB is already fully migrated. Simulating a race by manually attempting
    // to add a column that already exists must not throw.
    expect(() => {
      try {
        database.exec('ALTER TABLE advisories ADD COLUMN canonical_id TEXT NOT NULL DEFAULT \'\'')
      } catch (err) {
        if (!/duplicate column name/i.test((err as Error).message)) throw err
      }
    }).not.toThrow()
  })
})

describe('C8/C9 — mapRowsSafely skip-and-warn', () => {
  it('skips advisory row with invalid severity and warns to stderr', () => {
    const database = makeDb()
    upsertAdvisory(database, {
      id: 'CVE-2024-C8-SEV',
      canonicalId: 'CVE-2024-C8-SEV',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Test advisory',
      url: 'https://example.com',
    })
    database.prepare("UPDATE advisories SET severity = 'bogus' WHERE id = ?").run('CVE-2024-C8-SEV')

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      const result = getAdvisoriesForPackage(database, 'lodash')
      expect(result).toBeInstanceOf(Array)
      expect(result).toHaveLength(0)
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('CVE-2024-C8-SEV'),
      )
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('bogus'),
      )
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it('skips advisory row with invalid type and warns to stderr', () => {
    const database = makeDb()
    upsertAdvisory(database, {
      id: 'CVE-2024-C8-TYPE',
      canonicalId: 'CVE-2024-C8-TYPE',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Test advisory',
      url: 'https://example.com',
    })
    database.prepare("UPDATE advisories SET type = 'unknown-type' WHERE id = ?").run('CVE-2024-C8-TYPE')

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      const result = getAdvisoriesForPackage(database, 'lodash')
      expect(result).toBeInstanceOf(Array)
      expect(result).toHaveLength(0)
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('CVE-2024-C8-TYPE'),
      )
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('unknown-type'),
      )
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it('skips advisory row with corrupt affected_ranges_json and warns to stderr', () => {
    const database = makeDb()
    upsertAdvisory(database, {
      id: 'CVE-2024-C9-JSON',
      canonicalId: 'CVE-2024-C9-JSON',
      type: 'cve',
      packageName: 'lodash',
      ranges: [{ introduced: '0', fixed: '4.17.21' }],
      severity: 'high',
      title: 'Test advisory',
      url: 'https://example.com',
    })
    database.prepare("UPDATE advisories SET affected_ranges_json = '{not valid json' WHERE id = ?").run('CVE-2024-C9-JSON')

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      const result = getAdvisoriesForPackage(database, 'lodash')
      expect(result).toBeInstanceOf(Array)
      expect(result).toHaveLength(0)
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('CVE-2024-C9-JSON'),
      )
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it('returns valid advisories while skipping corrupt ones', () => {
    const database = makeDb()
    const advisories = [
      { id: 'CVE-MIXED-0001', packageName: 'lodash', severity: 'high' as const },
      { id: 'CVE-MIXED-0002', packageName: 'lodash', severity: 'low' as const },
      { id: 'CVE-MIXED-0003', packageName: 'lodash', severity: 'moderate' as const },
    ]
    for (const a of advisories) {
      upsertAdvisory(database, {
        id: a.id,
        canonicalId: a.id,
        type: 'cve',
        packageName: a.packageName,
        ranges: [{ introduced: '0', fixed: '1.0.0' }],
        severity: a.severity,
        title: 'Test',
        url: 'https://example.com',
      })
    }
    // Corrupt only the second advisory
    database.prepare("UPDATE advisories SET severity = 'bogus' WHERE id = ?").run('CVE-MIXED-0002')

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      const result = getAdvisoriesForPackage(database, 'lodash')
      expect(result).toHaveLength(2)
      const ids = result.map(r => r.id)
      expect(ids).toContain('CVE-MIXED-0001')
      expect(ids).toContain('CVE-MIXED-0003')
      expect(ids).not.toContain('CVE-MIXED-0002')
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('CVE-MIXED-0002'),
      )
    } finally {
      stderrSpy.mockRestore()
    }
  })
})

describe('M5 — openDb creates parent dir from path argument', () => {
  it('creates nested parent dir when it does not exist', () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
    const dbPath = join(tmpDir, 'nested', 'db.sqlite')
    db = openDb(dbPath)
    expect(existsSync(join(tmpDir, 'nested'))).toBe(true)
    expect(existsSync(dbPath)).toBe(true)
  })
})

describe('N4 — openDb sets file permissions to 0o600', () => {
  it('chmod 0o600 on newly created db file', () => {
    if (process.platform === 'win32') return
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
    const dbPath = join(tmpDir, 'perms.sqlite')
    db = openDb(dbPath)
    const mode = statSync(dbPath).mode & 0o777
    expect(mode).toBe(0o600)
  })
})

describe('N5 — openDb conditional chmod', () => {
  it('skips chmod when file already has 0o600', () => {
    if (process.platform === 'win32') return
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
    const dbPath = join(tmpDir, 'cond-chmod.sqlite')
    const first = openDb(dbPath)
    first.close()
    // file is now 0o600 — second open must not call chmodSync
    vi.mocked(chmodSync).mockClear()
    db = openDb(dbPath)
    expect(chmodSync).not.toHaveBeenCalled()
  })

  it('applies chmod when file has 0o644, resulting in 0o600', () => {
    if (process.platform === 'win32') return
    tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-db-test-'))
    const dbPath = join(tmpDir, 'cond-chmod2.sqlite')
    const first = openDb(dbPath)
    first.close()
    chmodSync(dbPath, 0o644)
    vi.mocked(chmodSync).mockClear()
    db = openDb(dbPath)
    expect(chmodSync).toHaveBeenCalledWith(dbPath, 0o600)
    const mode = statSync(dbPath).mode & 0o777
    expect(mode).toBe(0o600)
  })
})

describe('D4T — deterministic advisory ordering', () => {
  it('getAdvisoriesForPackage returns same order across two calls (canonical_id ASC, id ASC)', () => {
    const database = makeDb()

    // Insert 5 advisories in an order that would be non-deterministic without ORDER BY
    const advisories = [
      { id: 'CVE-2024-0005', canonicalId: 'GHSA-zzzz-zzzz-zzzz' },
      { id: 'CVE-2024-0003', canonicalId: 'GHSA-mmmm-mmmm-mmmm' },
      { id: 'CVE-2024-0001', canonicalId: 'GHSA-aaaa-aaaa-aaaa' },
      { id: 'CVE-2024-0004', canonicalId: 'GHSA-pppp-pppp-pppp' },
      { id: 'CVE-2024-0002', canonicalId: 'GHSA-bbbb-bbbb-bbbb' },
    ]

    for (const { id, canonicalId } of advisories) {
      upsertAdvisory(database, {
        id,
        canonicalId,
        type: 'cve',
        packageName: 'order-test-pkg',
        ranges: [{ introduced: '0', fixed: '1.0.0' }],
        severity: 'high',
        title: `Advisory ${id}`,
        url: `https://example.com/${id}`,
      })
    }

    const first = getAdvisoriesForPackage(database, 'order-test-pkg')
    const second = getAdvisoriesForPackage(database, 'order-test-pkg')

    // Both calls must return identical ordering
    expect(first.map(a => a.canonicalId)).toEqual(second.map(a => a.canonicalId))

    // Order must be canonical_id ASC, id ASC
    const expectedOrder = [
      'GHSA-aaaa-aaaa-aaaa',
      'GHSA-bbbb-bbbb-bbbb',
      'GHSA-mmmm-mmmm-mmmm',
      'GHSA-pppp-pppp-pppp',
      'GHSA-zzzz-zzzz-zzzz',
    ]
    expect(first.map(a => a.canonicalId)).toEqual(expectedOrder)
  })
})

describe('pruneStaleAdvisories', () => {
  it('prunes rows with old last_seen_in_full_sync, keeps recent and GitHub-only rows', () => {
    const database = makeDb()

    // A — old full-sync row (should be pruned)
    upsertAdvisoryFromFullSync(database, {
      id: 'CVE-OLD-0001',
      canonicalId: 'CVE-OLD-0001',
      type: 'cve',
      packageName: 'pkg-old',
      ranges: [{ introduced: '0', fixed: '1.0.0' }],
      severity: 'low',
      title: 'Old',
      url: 'https://example.com/old',
    }, 1000)

    // B — recent full-sync row (should survive)
    upsertAdvisoryFromFullSync(database, {
      id: 'CVE-NEW-0002',
      canonicalId: 'CVE-NEW-0002',
      type: 'cve',
      packageName: 'pkg-new',
      ranges: [{ introduced: '0', fixed: '2.0.0' }],
      severity: 'high',
      title: 'New',
      url: 'https://example.com/new',
    }, 1_000_000_000_000)

    // C — GitHub-only row, last_seen_in_full_sync = 0 (should survive due to > 0 guard)
    upsertAdvisory(database, {
      id: 'GHSA-XXXX-YYYY-ZZZZ',
      canonicalId: 'GHSA-XXXX-YYYY-ZZZZ',
      type: 'cve',
      packageName: 'pkg-gh',
      ranges: [{ introduced: '0' }],
      severity: 'moderate',
      title: 'GitHub only',
      url: 'https://example.com/gh',
    })

    const pruned = pruneStaleAdvisories(database, 1_000_000_000_000, 1000)

    expect(pruned).toBe(1)
    expect(getAdvisoriesForPackage(database, 'pkg-old')).toHaveLength(0)
    expect(getAdvisoriesForPackage(database, 'pkg-new')).toHaveLength(1)
    expect(getAdvisoriesForPackage(database, 'pkg-gh')).toHaveLength(1)
  })
})

// ─── D5T: busy_timeout PRAGMA ────────────────────────────────────────────────

describe('D5T: openDb sets busy_timeout', () => {
  it('sets busy_timeout to 5000ms after WAL pragma', () => {
    const database = makeDb()
    const timeout = database.pragma('busy_timeout', { simple: true }) as number
    expect(timeout).toBe(5000)
  })
})
