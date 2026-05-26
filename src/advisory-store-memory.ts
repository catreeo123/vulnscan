import type { Advisory, AdvisoryStore } from './types.js'

export class InMemoryAdvisoryStore implements AdvisoryStore {
  private advisories = new Map<string, Advisory>()
  private syncMeta = new Map<string, number>()
  private fullSyncTimestamps = new Map<string, number>()

  getForPackage(name: string): Advisory[] {
    return [...this.advisories.values()].filter(a => a.packageName === name)
  }

  upsert(advisory: Advisory): void {
    this.advisories.set(`${advisory.id}:${advisory.packageName}`, advisory)
  }

  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void {
    const key = `${advisory.id}:${advisory.packageName}`
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
