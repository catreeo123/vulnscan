import { describe, it, expect } from 'vitest'
import { scrubSecrets } from './secrets.js'

describe('scrubSecrets', () => {
  it('leaves plain error messages untouched', () => {
    expect(scrubSecrets('plain error without secrets')).toBe('plain error without secrets')
  })

  it('leaves CVE identifiers untouched', () => {
    expect(scrubSecrets('CVE-2024-1234')).toBe('CVE-2024-1234')
  })

  it('redacts Bearer token', () => {
    const result = scrubSecrets('Authorization: Bearer ghp_abc123xyz456abc123xyz456')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('ghp_abc123xyz456abc123xyz456')
  })

  it('redacts ghp_ token', () => {
    const result = scrubSecrets('request failed with ghp_abc123xyz456abc123xyz456abc')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('ghp_abc123xyz456abc123xyz456abc')
  })

  it('redacts gho_ token', () => {
    const result = scrubSecrets('error: gho_abc123xyz456abc123xyz456abc')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('gho_abc123xyz456abc123xyz456abc')
  })

  it('redacts ghs_ token', () => {
    const result = scrubSecrets('token: ghs_abc123xyz456abc123xyz456abc')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('ghs_abc123xyz456abc123xyz456abc')
  })

  it('redacts Authorization header value', () => {
    const result = scrubSecrets('Authorization: Bearer mytoken123abc')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('mytoken123abc')
  })

  it('does not redact short token-like strings below ghp_ prefix', () => {
    // A message without any known secret prefix stays unchanged
    expect(scrubSecrets('failed to parse response')).toBe('failed to parse response')
  })

  it('redacts github_pat_ fine-grained PAT', () => {
    const result = scrubSecrets(
      'Error: github_pat_11ABCDEFGHIJK0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ failed',
    )
    expect(result).toContain('github_pat_[REDACTED]')
    expect(result).not.toContain('github_pat_11ABCDEFGHIJK0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ')
  })
})
