/**
 * Advisory source identity. Centralizes the 'osv' / 'github' literals scattered across
 * local-db.ts and sync-orchestrator.ts (#53) so the "only OSV is prunable; GitHub columns
 * are curated" invariant can't drift via a typo'd literal at one of the many guard sites.
 */
export const ADVISORY_SOURCE = {
  OSV: 'osv',
  GITHUB: 'github',
} as const

export type AdvisorySource = (typeof ADVISORY_SOURCE)[keyof typeof ADVISORY_SOURCE]
