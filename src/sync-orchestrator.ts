import type { AdvisoryStore } from './types.js'
import { syncOsv } from './osv-sync.js'
import { syncGithubAdvisories } from './github-advisory-sync.js'
import { scrubSecrets } from './secrets.js'

const DEFAULT_STALENESS_MS = 24 * 60 * 60 * 1000

const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000

export async function syncIfStale(
  store: AdvisoryStore,
  stalenessMs = DEFAULT_STALENESS_MS,
): Promise<boolean> {
  const osvLast = store.getLastSyncedAt('osv')
  const ghLast = store.getLastSyncedAt('github')
  const now = Date.now()

  const osvStale = osvLast === null || now - osvLast > stalenessMs
  const ghStale = ghLast === null || now - ghLast > stalenessMs

  if (!osvStale && !ghStale) return false

  if (osvStale) {
    const { fullSyncStartedAt } = await syncOsv(store)
    store.pruneStale(fullSyncStartedAt, GRACE_PERIOD_MS)
    store.setLastSyncedAt('osv', Date.now())
  }
  if (ghStale) await syncGithubSafe(store)
  return true
}

// runSync always does a full sync (no staleness check, no since filter).
// Used by the `update` command where the user explicitly requests a fresh pull.
export async function runSync(store: AdvisoryStore): Promise<void> {
  const { fullSyncStartedAt } = await syncOsv(store)
  await syncGithubSafe(store)
  store.pruneStale(fullSyncStartedAt, GRACE_PERIOD_MS)
  store.setLastSyncedAt('osv', Date.now())
}

async function syncGithubSafe(store: AdvisoryStore): Promise<void> {
  const since = store.getLastSyncedAt('github') ?? undefined
  try {
    await syncGithubAdvisories(store, since)
  } catch (err) {
    process.stderr.write(
      `GitHub Advisory: sync failed (${scrubSecrets((err as Error).message)}) — proceeding with OSV data only\n`,
    )
  }
}
