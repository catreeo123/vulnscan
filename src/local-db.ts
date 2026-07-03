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
  db.pragma('busy_timeout = 5000')
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
      source TEXT NOT NULL DEFAULT '',
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
  if (!cols.has('source')) {
    safeAddColumn(db, `source TEXT NOT NULL DEFAULT ''`)
    // Backfill source for pre-migration rows from the advisory url so the source-aware
    // prune below can tell OSV rows (prunable) from GitHub rows (exempt). Unknown urls
    // stay '' and are never pruned (conservative — never silently drop an Advisory).
    db.exec(`UPDATE advisories SET source = 'github' WHERE source = '' AND url LIKE '%github.com%'`)
    db.exec(`UPDATE advisories SET source = 'osv' WHERE source = '' AND url LIKE '%osv.dev%'`)
  }
  return db
}

// The GitHub Source upsert. It stamps source='github' so pruneStaleAdvisories (an OSV
// full-Sync operation) never deletes it: GitHub Sync is incremental, so a static advisory
// is upserted once and its last_seen_in_full_sync then freezes — the source tag, not a
// fresh timestamp, is what keeps it from being stale-pruned.
export function upsertAdvisory(db: Database.Database, advisory: Advisory): void {
  const now = Date.now()
  db.prepare(`
    INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url, canonical_id, synced_at, last_seen_in_full_sync, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'github')
    ON CONFLICT (id, package_name) DO UPDATE SET
      -- Malware classification is sticky: never let a later cve-typed write (e.g. GitHub's reviewed
      -- pass colliding with an OSV MAL-* entry that carries a CVE alias) downgrade an existing
      -- malware row to a plain CVE and drop it below the fail threshold. A cve→mal upgrade
      -- (GitHub's malware pass promoting a row) is still allowed.
      type = CASE WHEN advisories.type = 'mal' THEN advisories.type ELSE excluded.type END,
      affected_ranges_json = excluded.affected_ranges_json,
      severity = CASE WHEN advisories.type = 'mal' AND excluded.type != 'mal' THEN advisories.severity ELSE excluded.severity END,
      -- A blocked mal→cve downgrade (above) must not leave a mixed row: keep the malware
      -- advisory's own title/url instead of taking the (blocked) cve write's values (#56).
      title = CASE WHEN advisories.type = 'mal' AND excluded.type != 'mal' THEN advisories.title ELSE excluded.title END,
      url = CASE WHEN advisories.type = 'mal' AND excluded.type != 'mal' THEN advisories.url ELSE excluded.url END,
      canonical_id = excluded.canonical_id,
      synced_at = excluded.synced_at,
      last_seen_in_full_sync = excluded.last_seen_in_full_sync,
      source = excluded.source
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
    INSERT INTO advisories (id, type, package_name, affected_ranges_json, severity, title, url, canonical_id, synced_at, last_seen_in_full_sync, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'osv')
    ON CONFLICT (id, package_name) DO UPDATE SET
      -- Preserve a GitHub row's malware classification: a GHSA-id malware advisory (type='mal')
      -- can collide with an OSV mirror that derives type='cve' (no MAL-/CVE alias). Overwriting
      -- would relabel it 'cve' and drop the malware signal downstream consumers key on.
      type = CASE WHEN advisories.source = 'github' THEN advisories.type ELSE excluded.type END,
      -- A CVE-numbered advisory shares its PK (id, package_name) across both feeds (getBestId
      -- prefers the CVE alias = GitHub's id), so an OSV full sync collides with a GitHub row.
      -- An OSV full sync must NOT degrade GitHub's curated vulnerability data: the OSV mirror
      -- frequently lags GitHub (fewer/narrower ranges, lower severity), and overwriting would
      -- silently drop coverage for versions only GitHub lists (false negative) or lower the
      -- severity below the fail threshold. GitHub's own incremental sync keeps these rows current.
      affected_ranges_json = CASE WHEN advisories.source = 'github' THEN advisories.affected_ranges_json ELSE excluded.affected_ranges_json END,
      severity = CASE WHEN advisories.source = 'github' THEN advisories.severity ELSE excluded.severity END,
      -- title/url are part of the documented output contract (rendered verbatim in --format json)
      -- and, like the guarded columns above, must keep GitHub's curated values on collision: an OSV
      -- mirror's generic osv.dev summary/link must not overwrite GitHub's advisory reference.
      title = CASE WHEN advisories.source = 'github' THEN advisories.title ELSE excluded.title END,
      url = CASE WHEN advisories.source = 'github' THEN advisories.url ELSE excluded.url END,
      -- canonical_id is the stable cross-source identifier (GitHub stores the GHSA id). An OSV
      -- mirror lacking a GHSA alias derives a CVE-id canonical_id; overwriting would make a
      -- GitHub row's identity sync-order-dependent and break dedup/suppression keyed on the GHSA.
      canonical_id = CASE WHEN advisories.source = 'github' THEN advisories.canonical_id ELSE excluded.canonical_id END,
      synced_at = excluded.synced_at,
      last_seen_in_full_sync = excluded.last_seen_in_full_sync,
      -- Never downgrade a GitHub-Source row to 'osv', or it would be re-exposed to the OSV
      -- stale-prune once OSV drops it (silent false negative).
      source = CASE WHEN advisories.source = 'github' THEN 'github' ELSE excluded.source END
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
  // Only OSV-Source advisories are prunable: the OSV full dump is authoritative for what
  // still exists, so a row missing from it past the grace window is genuinely stale. GitHub
  // Source advisories are exempt — GitHub Sync is incremental and never re-confirms a static
  // advisory, so pruning by timestamp alone would silently drop live Findings (B2/#49).
  const result = db.prepare(
    "DELETE FROM advisories WHERE source = 'osv' AND last_seen_in_full_sync < ? AND last_seen_in_full_sync > 0",
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
  const rows = db.prepare('SELECT * FROM advisories WHERE package_name = ? ORDER BY canonical_id ASC, id ASC').all(packageName) as AdvisoryRow[]
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
