import type Database from 'better-sqlite3'
import { getLastSyncedAt, pruneStaleAdvisories } from './local-db.js'
import { syncOsv } from './osv-sync.js'
import { syncGithubAdvisories } from './github-advisory-sync.js'
import { scrubSecrets } from './secrets.js'

const DEFAULT_STALENESS_MS = 24 * 60 * 60 * 1000

const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000

export async function syncIfStale(
  db: Database.Database,
  stalenessMs = DEFAULT_STALENESS_MS,
): Promise<boolean> {
  const osvLast = getLastSyncedAt(db, 'osv')
  const ghLast = getLastSyncedAt(db, 'github')
  const now = Date.now()

  const osvStale = osvLast === null || now - osvLast > stalenessMs
  const ghStale = ghLast === null || now - ghLast > stalenessMs

  if (!osvStale && !ghStale) return false

  if (osvStale) {
    const { fullSyncStartedAt } = await syncOsv(db)
    pruneStaleAdvisories(db, fullSyncStartedAt, GRACE_PERIOD_MS)
  }
  if (ghStale) await syncGithubSafe(db)
  return true
}

// runSync always does a full sync (no staleness check, no since filter).
// Used by the `update` command where the user explicitly requests a fresh pull.
export async function runSync(db: Database.Database): Promise<void> {
  const { fullSyncStartedAt } = await syncOsv(db)
  await syncGithubSafe(db)
  pruneStaleAdvisories(db, fullSyncStartedAt, GRACE_PERIOD_MS)
}

async function syncGithubSafe(db: Database.Database): Promise<void> {
  const since = getLastSyncedAt(db, 'github') ?? undefined
  try {
    await syncGithubAdvisories(db, since)
  } catch (err) {
    process.stderr.write(
      `GitHub Advisory: sync failed (${scrubSecrets((err as Error).message)}) — proceeding with OSV data only\n`,
    )
  }
}
