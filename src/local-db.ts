import Database from 'better-sqlite3'
import { homedir } from 'node:os'
import * as fs from 'node:fs'
import { join, dirname } from 'node:path'
import type { Advisory, SemverRange, Severity } from './types.js'

export const DB_PATH = process.env.VULNSCAN_DB_PATH ?? join(homedir(), '.vulnscan', 'db.sqlite')

// Wraps ALTER TABLE ADD COLUMN, swallowing "duplicate column name" so concurrent
// openDb calls on the same WAL DB don't crash if both race past the PRAGMA check.
function safeAddColumn(db: Database.Database, definition: string): void {
  try {
    db.exec(`ALTER TABLE advisories ADD COLUMN ${definition}`)
  } catch (err) {
    if (!/duplicate column name/i.test((err as Error).message)) throw err
  }
}

type AdvisoryRow = {
  id: string
  type: string
  package_name: string
  affected_ranges_json: string
  severity: string
  title: string
  url: string
  canonical_id: string
}

export function openDb(path = DB_PATH): Database.Database {
  fs.mkdirSync(dirname(path), { recursive: true })
  const db = new Database(path)
  let needsChmod = true
  try {
    needsChmod = (fs.statSync(path).mode & 0o777) !== 0o600
  } catch {
    // stat failed (should not happen after new Database, but be defensive)
  }
  if (needsChmod) {
    try {
      fs.chmodSync(path, 0o600)
    } catch (err) {
      process.stderr.write(`Warning: chmod 0o600 on ${path} failed: ${(err as Error).message}\n`)
    }
  }
  db.pragma('journal_mode = WAL')
  db.exec(`
    CREATE TABLE IF NOT EXISTS advisories (
      id TEXT NOT NULL,
      type TEXT NOT NULL,
      package_name TEXT NOT NULL,
      affected_ranges_json TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      canonical_id TEXT NOT NULL DEFAULT '',
      synced_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER) * 1000),
      last_seen_in_full_sync INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (id, package_name)
    );
    CREATE INDEX IF NOT EXISTS idx_advisories_pkg ON advisories(package_name);
    CREATE TABLE IF NOT EXISTS sync_metadata (
      source TEXT PRIMARY KEY,
      last_synced_at INTEGER NOT NULL
    );
  `)
  const tableInfo = db.prepare('PRAGMA table_info(advisories)').all() as Array<{ name: string }>
  const cols = new Set(tableInfo.map(c => c.name))
  if (!cols.has('synced_at')) {
    safeAddColumn(db, `synced_at INTEGER NOT NULL DEFAULT 0`)
  }
  if (!cols.has('last_seen_in_full_sync')) {
    safeAddColumn(db, `last_seen_in_full_sync INTEGER NOT NULL DEFAULT 0`)
  }
  if (!cols.has('canonical_id')) {
    safeAddColumn(db, `canonical_id TEXT NOT NULL DEFAULT ''`)
    // Backfill canonical_id from URL for rows that predate this column.
    const rows = db.prepare(
      `SELECT id, package_name, url FROM advisories WHERE canonical_id = '' AND url LIKE '%GHSA-%'`
    ).all() as Array<{ id: string; package_name: string; url: string }>
    if (rows.length > 0) {
      const update = db.prepare(`UPDATE advisories SET canonical_id = ? WHERE id = ? AND package_name = ?`)
      const tx = db.transaction((items: typeof rows) => {
        for (const r of items) {
          const m = r.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)
          if (m) update.run(m[0].toUpperCase(), r.id, r.package_name)
        }
      })
      tx(rows)
    }
  }
  return db
}

// last_seen_in_full_sync records "last touched by any source" (not strictly full-sync only).
// The GH path sets it to Date.now() so a GH-tracked advisory is never stale-pruned.
export function upsertAdvisory(db: Database.Database, advisory: Advisory): void {
  const now = Date.now()
  db.prepare(`
    INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url, canonical_id, synced_at, last_seen_in_full_sync)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (id, package_name) DO UPDATE SET
      type = excluded.type,
      affected_ranges_json = excluded.affected_ranges_json,
      severity = excluded.severity,
      title = excluded.title,
      url = excluded.url,
      canonical_id = excluded.canonical_id,
      synced_at = excluded.synced_at,
      last_seen_in_full_sync = excluded.last_seen_in_full_sync
  `).run(
    advisory.id,
    advisory.type,
    advisory.packageName,
    JSON.stringify(advisory.ranges),
    advisory.severity,
    advisory.title,
    advisory.url,
    advisory.canonicalId,
    now,
    now,
  )
}

export function upsertAdvisoryFromFullSync(
  db: Database.Database,
  advisory: Advisory,
  fullSyncStartedAt: number,
): void {
  db.prepare(`
    INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url, canonical_id, synced_at, last_seen_in_full_sync)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (id, package_name) DO UPDATE SET
      type = excluded.type,
      affected_ranges_json = excluded.affected_ranges_json,
      severity = excluded.severity,
      title = excluded.title,
      url = excluded.url,
      canonical_id = excluded.canonical_id,
      synced_at = excluded.synced_at,
      last_seen_in_full_sync = excluded.last_seen_in_full_sync
  `).run(
    advisory.id,
    advisory.type,
    advisory.packageName,
    JSON.stringify(advisory.ranges),
    advisory.severity,
    advisory.title,
    advisory.url,
    advisory.canonicalId,
    Date.now(),
    fullSyncStartedAt,
  )
}

export function pruneStaleAdvisories(
  db: Database.Database,
  fullSyncStartedAt: number,
  gracePeriodMs: number,
): number {
  const cutoff = fullSyncStartedAt - gracePeriodMs
  const result = db.prepare(
    'DELETE FROM advisories WHERE last_seen_in_full_sync < ? AND last_seen_in_full_sync > 0',
  ).run(cutoff)
  return result.changes
}

function mapRowsSafely(rows: AdvisoryRow[]): Advisory[] {
  const result: Advisory[] = []
  for (const row of rows) {
    try {
      result.push(rowToAdvisory(row))
    } catch (err) {
      process.stderr.write(
        `Warning: skipping advisory ${row.id ?? '<unknown>'}: ${(err as Error).message}\n`,
      )
    }
  }
  return result
}

export function getAdvisoriesForPackage(db: Database.Database, packageName: string): Advisory[] {
  const rows = db.prepare('SELECT * FROM advisories WHERE package_name = ?').all(packageName) as AdvisoryRow[]
  return mapRowsSafely(rows)
}

export function getAllAdvisories(db: Database.Database): Advisory[] {
  const rows = db.prepare('SELECT * FROM advisories').all() as AdvisoryRow[]
  return mapRowsSafely(rows)
}

export function setLastSyncedAt(db: Database.Database, source: string, timestamp: number): void {
  db.prepare('INSERT OR REPLACE INTO sync_metadata (source, last_synced_at) VALUES (?, ?)').run(source, timestamp)
}

export function getLastSyncedAt(db: Database.Database, source: string): number | null {
  const row = db.prepare('SELECT last_synced_at FROM sync_metadata WHERE source = ?').get(source) as
    | { last_synced_at: number }
    | undefined
  return row?.last_synced_at ?? null
}

export function advisoryCount(db: Database.Database): number {
  const row = db.prepare('SELECT COUNT(*) as n FROM advisories').get() as { n: number }
  return row.n
}

const VALID_SEVERITIES = ['critical', 'high', 'moderate', 'low'] as const
const VALID_TYPES = ['cve', 'mal'] as const

function rowToAdvisory(row: AdvisoryRow): Advisory {
  if (!(VALID_SEVERITIES as readonly string[]).includes(row.severity)) {
    throw new Error(`Advisory ${row.id} has invalid severity '${row.severity}' (expected one of ${VALID_SEVERITIES.join(', ')})`)
  }
  if (!(VALID_TYPES as readonly string[]).includes(row.type)) {
    throw new Error(`Advisory ${row.id} has invalid type '${row.type}' (expected one of ${VALID_TYPES.join(', ')})`)
  }
  return {
    id: row.id,
    canonicalId: row.canonical_id !== '' ? row.canonical_id : row.id,
    type: row.type as 'cve' | 'mal',
    packageName: row.package_name,
    ranges: JSON.parse(row.affected_ranges_json) as SemverRange[],
    severity: row.severity as Severity,
    title: row.title,
    url: row.url,
  }
}
