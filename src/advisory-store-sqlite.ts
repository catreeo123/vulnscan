import type { Advisory, AdvisoryStore } from './types.js'
import {
  openDb,
  upsertAdvisory,
  upsertAdvisoryFromFullSync,
  pruneStaleAdvisories,
  getAdvisoriesForPackage,
  setLastSyncedAt,
  getLastSyncedAt,
  advisoryCount,
} from './local-db.js'
import type Database from 'better-sqlite3'

export class SqliteAdvisoryStore implements AdvisoryStore {
  private db: Database.Database

  constructor(db: Database.Database) {
    this.db = db
  }

  getForPackage(name: string): Advisory[] {
    return getAdvisoriesForPackage(this.db, name)
  }

  upsert(advisory: Advisory): void {
    upsertAdvisory(this.db, advisory)
  }

  upsertFromFullSync(advisory: Advisory, fullSyncStartedAt: number): void {
    upsertAdvisoryFromFullSync(this.db, advisory, fullSyncStartedAt)
  }

  count(): number {
    return advisoryCount(this.db)
  }

  pruneStale(fullSyncStartedAt: number, gracePeriodMs: number): void {
    pruneStaleAdvisories(this.db, fullSyncStartedAt, gracePeriodMs)
  }

  getLastSyncedAt(source: string): number | null {
    return getLastSyncedAt(this.db, source)
  }

  setLastSyncedAt(source: string, ts: number): void {
    setLastSyncedAt(this.db, source, ts)
  }

  close(): void {
    this.db.close()
  }
}

export function openStore(path?: string): AdvisoryStore {
  return new SqliteAdvisoryStore(openDb(path))
}
