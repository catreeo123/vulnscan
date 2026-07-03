import type { AdvisoryStore } from './types.js'
import { syncOsv } from './osv-sync.js'
import { syncGithubAdvisories } from './github-advisory-sync.js'
import { scrubSecrets } from './secrets.js'
import { incomplete, informational } from './warnings.js'
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

  const warnings: ScanWarning[] = []

  if (osvSkew) {
    warnings.push(informational('clock skew detected: OSV advisory database was last synced in the future; forcing re-sync'))
  }
  if (ghSkew) {
    warnings.push(informational('clock skew detected: GitHub advisory database was last synced in the future; forcing re-sync'))
  }

  // Double-check: a parallel process may have refreshed cursors while we were deciding.
  const osvLastAgain = store.getLastSyncedAt('osv')
  const ghLastAgain = store.getLastSyncedAt('github')
  const nowAgain = Date.now()
  const osvStillStale = osvStale && (osvLastAgain === null || nowAgain < osvLastAgain || nowAgain - osvLastAgain > stalenessMs)
  const ghStillStale = ghStale && (ghLastAgain === null || nowAgain < ghLastAgain || nowAgain - ghLastAgain > stalenessMs)

  if (!osvStillStale && !ghStillStale) return warnings

  if (osvStillStale) {
    // OSV download is untrusted external infra; a transient HTTP/network failure must degrade
    // to an `incomplete` warning (exit 2) — letting the Scan proceed against existing Local DB
    // data — not crash out with exit 1 (which signals "findings"). Mirrors syncGithubSafe.
    // Only the network Sync is guarded: a pruneStale/cursor failure is a local invariant and
    // must still propagate (and must not advance the OSV cursor — see orchestrator tests).
    let osvResult: Awaited<ReturnType<typeof syncOsv>> | null = null
    try {
      osvResult = await syncOsv(store)
    } catch (err) {
      const scrubbed = scrubSecrets((err as Error).message)
      process.stderr.write(`OSV: sync failed (${scrubbed}) — proceeding with existing local data\n`)
      warnings.push(incomplete(`OSV sync failed: ${scrubbed}`))
    }
    if (osvResult) {
      const { fullSyncStartedAt, warnings: osvWarnings } = osvResult
      for (const w of osvWarnings) warnings.push(w)
      store.pruneStale(fullSyncStartedAt, GRACE_PERIOD_MS)
      store.setLastSyncedAt('osv', Date.now())
    }
  }
  if (ghStillStale) {
    const ghWarnings = await syncGithubSafe(store)
    for (const w of ghWarnings) warnings.push(w)
  }
  return warnings
}

// runSync forces a full OSV pull and a GitHub sync (the latter is incremental from the
// stored cursor by design — warm-start + incremental is the CI refresh strategy).
// Used by the `update` command. Returns the collected warnings so the caller can fail
// safe (exit 2) on an `incomplete` sync instead of silently publishing degraded data.
export async function runSync(store: AdvisoryStore): Promise<ScanWarning[]> {
  // Build with push-loops, not spread — the warning arrays can be huge (issue #24).
  const warnings: ScanWarning[] = []

  // OSV bulk download is untrusted external infra: a transient network/HTTP failure must
  // degrade to an `incomplete` warning (exit 2 — data may be missing) instead of propagating
  // as an unhandled throw, which the CLI's top-level catch maps to exit 1 ("findings"). This
  // mirrors syncIfStale and the GitHub path (syncGithubSafe is already guarded). A successful
  // pull is required before pruning/advancing the OSV cursor — a failed sync must not delete
  // live advisories against partial data, nor mask itself as a fresh successful sync.
  let osvResult: Awaited<ReturnType<typeof syncOsv>> | null = null
  try {
    osvResult = await syncOsv(store)
  } catch (err) {
    const scrubbed = scrubSecrets((err as Error).message)
    process.stderr.write(`OSV: sync failed (${scrubbed}) — proceeding with existing local data\n`)
    warnings.push(incomplete(`OSV sync failed: ${scrubbed}`))
  }

  const ghWarnings = await syncGithubSafe(store)

  if (osvResult) {
    store.pruneStale(osvResult.fullSyncStartedAt, GRACE_PERIOD_MS)
    store.setLastSyncedAt('osv', Date.now())
    for (const w of osvResult.warnings) warnings.push(w)
  }
  for (const w of ghWarnings) {
    warnings.push(w)
    process.stderr.write(`warning: ${w.message}\n`)
  }
  return warnings
}

async function syncGithubSafe(store: AdvisoryStore): Promise<ScanWarning[]> {
  const stored = store.getLastSyncedAt('github')
  // Reject a future cursor (clock skew): using it as the `updated>=` filter would match nothing,
  // then syncGithubAdvisories advances the cursor to now — silently erasing the window between the
  // true last-good sync and now. Fall back to a full pull (since=undefined), mirroring OSV.
  const since = stored !== null && stored <= Date.now() ? stored : undefined
  try {
    const { warnings } = await syncGithubAdvisories(store, since)
    return warnings
  } catch (err) {
    const scrubbed = scrubSecrets((err as Error).message)
    process.stderr.write(
      `GitHub Advisory: sync failed (${scrubbed}) — proceeding with OSV data only\n`,
    )
    return [incomplete(`GitHub Advisory sync failed: ${scrubbed}`)]
  }
}
