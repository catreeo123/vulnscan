import type { AdvisoryStore } from './types.js'
import { syncOsv } from './osv-sync.js'
import { syncGithubAdvisories } from './github-advisory-sync.js'
import { scrubSecrets } from './secrets.js'
import { informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

const DEFAULT_STALENESS_MS = 24 * 60 * 60 * 1000

const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000

export async function syncIfStale(
  store: AdvisoryStore,
  stalenessMs = DEFAULT_STALENESS_MS,
): Promise<ScanWarning[]> {
  const osvLast = store.getLastSyncedAt('osv')
  const ghLast = store.getLastSyncedAt('github')
  const now = Date.now()

  const osvSkew = osvLast !== null && now < osvLast
  const ghSkew = ghLast !== null && now < ghLast

  const osvStale = osvLast === null || osvSkew || now - osvLast > stalenessMs
  const ghStale = ghLast === null || ghSkew || now - ghLast > stalenessMs

  if (!osvStale && !ghStale) return []

  // Double-check: a parallel process may have refreshed cursors while we were deciding.
  const osvLastAgain = store.getLastSyncedAt('osv')
  const ghLastAgain = store.getLastSyncedAt('github')
  const nowAgain = Date.now()
  const osvStillStale = osvStale && (osvLastAgain === null || nowAgain < osvLastAgain || nowAgain - osvLastAgain > stalenessMs)
  const ghStillStale = ghStale && (ghLastAgain === null || nowAgain < ghLastAgain || nowAgain - ghLastAgain > stalenessMs)

  if (!osvStillStale && !ghStillStale) return []

  const warnings: ScanWarning[] = []

  if (osvSkew) {
    warnings.push(informational('clock skew detected: OSV advisory database was last synced in the future; forcing re-sync'))
  }
  if (ghSkew) {
    warnings.push(informational('clock skew detected: GitHub advisory database was last synced in the future; forcing re-sync'))
  }

  if (osvStillStale) {
    const { fullSyncStartedAt } = await syncOsv(store)
    store.pruneStale(fullSyncStartedAt, GRACE_PERIOD_MS)
    store.setLastSyncedAt('osv', Date.now())
  }
  if (ghStillStale) {
    const ghWarnings = await syncGithubSafe(store)
    warnings.push(...ghWarnings)
  }
  return warnings
}

// runSync always does a full sync (no staleness check, no since filter).
// Used by the `update` command where the user explicitly requests a fresh pull.
export async function runSync(store: AdvisoryStore): Promise<void> {
  const { fullSyncStartedAt } = await syncOsv(store)
  await syncGithubSafe(store)
  store.pruneStale(fullSyncStartedAt, GRACE_PERIOD_MS)
  store.setLastSyncedAt('osv', Date.now())
}

async function syncGithubSafe(store: AdvisoryStore): Promise<ScanWarning[]> {
  const since = store.getLastSyncedAt('github') ?? undefined
  try {
    const { warnings } = await syncGithubAdvisories(store, since)
    return warnings
  } catch (err) {
    process.stderr.write(
      `GitHub Advisory: sync failed (${scrubSecrets((err as Error).message)}) — proceeding with OSV data only\n`,
    )
    return []
  }
}
