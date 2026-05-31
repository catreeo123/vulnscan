import { describe, it, expect } from 'vitest'
import { incomplete, informational, hasIncomplete } from './warnings.js'
import type { ScanWarning } from './warnings.js'

describe('incomplete()', () => {
  it('returns ScanWarning with class "incomplete"', () => {
    const w = incomplete('v1 lockfile not supported')
    expect(w).toEqual<ScanWarning>({ class: 'incomplete', message: 'v1 lockfile not supported' })
  })

  it('preserves the message string verbatim', () => {
    const msg = 'git-sourced dep skipped (cannot check version range)'
    expect(incomplete(msg).message).toBe(msg)
  })
})

describe('informational()', () => {
  it('returns ScanWarning with class "informational"', () => {
    const w = informational('alias resolved to lodash')
    expect(w).toEqual<ScanWarning>({ class: 'informational', message: 'alias resolved to lodash' })
  })

  it('preserves the message string verbatim', () => {
    const msg = 'some info note'
    expect(informational(msg).message).toBe(msg)
  })
})

describe('hasIncomplete()', () => {
  it('returns false for empty array', () => {
    expect(hasIncomplete([])).toBe(false)
  })

  it('returns false when all warnings are informational', () => {
    expect(hasIncomplete([informational('a'), informational('b')])).toBe(false)
  })

  it('returns true when at least one warning is incomplete', () => {
    expect(hasIncomplete([informational('a'), incomplete('b')])).toBe(true)
  })

  it('returns true when all warnings are incomplete', () => {
    expect(hasIncomplete([incomplete('x'), incomplete('y')])).toBe(true)
  })
})
