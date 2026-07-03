import type { Advisory, AdvisoryStore } from './types.js'

export class InMemoryAdvisoryStore implements AdvisoryStore {
  private advisories = new Map<string, Advisory>()
  private syncMeta = new Map<string, number>()
  private fullSyncTimestamps = new Map<string, number>()
  private githubKeys = new Set<string>()

  getForPackage(name: string): Advisory[] {
    return [...this.advisories.values()]
      .filter(a => a.packageName === name)
      .sort((a, b) => {
        const cmp = a.canonicalId.localeCompare(b.canonicalId)
        return cmp !== 0 ? cmp : a.id.localeCompare(b.id)
      })
  }

  upsert(advisory: Advisory): void {
    const key = `${advisory.id}:${advisory.packageName}`
    this.advisories.set(key, advisory)
    // upsert() is only ever called for GitHub-sourced advisories (upsertFromFullSync is the OSV
    // path). Mirrors SQLite's upsertAdvisory stamping source='github' on the row, which permanently
    // exempts it from pruneStaleAdvisories's 'osv'-only filter — a stale fullSyncTimestamps entry
    // from an earlier OSV full sync must not survive to prune a row GitHub has since re-touched.
    this.fullSyncTimestamps.delete(key)
    this.githubKeys.add(key)
  }

  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void {
    const key = `${advisory.id}:${advisory.packageName}`
    // Mirrors SQLite's upsertAdvisoryFromFullSync source='github' guard: an OSV full sync must
    // not overwrite a GitHub-sourced row's data, nor re-expose it to future pruning by re-adding
    // a fullSyncTimestamps entry — a later collision here would otherwise silently undo the
    // permanent exemption upsert() just established (#45).
    if (this.githubKeys.has(key)) return
    this.advisories.set(key, advisory)
    this.fullSyncTimestamps.set(key, fullSyncStartedAt)
  }

  count(): number {
    return this.advisories.size
  }

  pruneStale(fullSyncStartedAt: number, gracePeriodMs: number): void {
    const cutoff = fullSyncStartedAt - gracePeriodMs
    for (const [key, ts] of this.fullSyncTimestamps) {
      if (ts < cutoff) {
        this.advisories.delete(key)
        this.fullSyncTimestamps.delete(key)
      }
    }
  }

  getLastSyncedAt(source: string): number | null {
    return this.syncMeta.get(source) ?? null
  }

  setLastSyncedAt(source: string, ts: number): void {
    this.syncMeta.set(source, ts)
  }

  close(): void {}
}
