import { it, expect, describe } from 'vitest'
import { mapSeverity, resolveAdvisorySeverity } from './severity-mapper.js'

describe('mapSeverity — known labels', () => {
  it('maps CRITICAL (case-insensitive) to critical with no warning', () => {
    const result = mapSeverity({ label: 'CRITICAL', advisoryId: 'GHSA-1111-1111-1111' })
    expect(result.severity).toBe('critical')
    expect(result.warning).toBeUndefined()
  })

  it('maps critical (lowercase) to critical', () => {
    const result = mapSeverity({ label: 'critical', advisoryId: 'GHSA-1111-1111-1111' })
    expect(result.severity).toBe('critical')
    expect(result.warning).toBeUndefined()
  })

  it('maps HIGH to high with no warning', () => {
    const result = mapSeverity({ label: 'HIGH', advisoryId: 'GHSA-2222-2222-2222' })
    expect(result.severity).toBe('high')
    expect(result.warning).toBeUndefined()
  })

  it('maps MODERATE to moderate with no warning', () => {
    const result = mapSeverity({ label: 'MODERATE', advisoryId: 'GHSA-3333-3333-3333' })
    expect(result.severity).toBe('moderate')
    expect(result.warning).toBeUndefined()
  })

  it('maps MEDIUM to moderate with no warning', () => {
    const result = mapSeverity({ label: 'MEDIUM', advisoryId: 'GHSA-3333-3333-3333' })
    expect(result.severity).toBe('moderate')
    expect(result.warning).toBeUndefined()
  })

  it('maps LOW to low with no warning', () => {
    const result = mapSeverity({ label: 'LOW', advisoryId: 'GHSA-4444-4444-4444' })
    expect(result.severity).toBe('low')
    expect(result.warning).toBeUndefined()
  })
})

describe('mapSeverity — fail-safe escalation', () => {
  it('escalates UNKNOWN label to high and emits informational warning', () => {
    const result = mapSeverity({ label: 'UNKNOWN', advisoryId: 'GHSA-aaaa-bbbb-cccc' })
    expect(result.severity).toBe('high')
    expect(result.warning).toBeDefined()
    expect(result.warning!.class).toBe('informational')
    expect(result.warning!.message).toContain('GHSA-aaaa-bbbb-cccc')
  })

  it('escalates missing label (undefined) to high and emits warning containing advisory id', () => {
    const result = mapSeverity({ label: undefined, advisoryId: 'CVE-2024-12345' })
    expect(result.severity).toBe('high')
    expect(result.warning).toBeDefined()
    expect(result.warning!.class).toBe('informational')
    expect(result.warning!.message).toContain('CVE-2024-12345')
  })

  it('escalates empty string label to high and emits informational warning', () => {
    const result = mapSeverity({ label: '', advisoryId: 'GHSA-zzzz-yyyy-xxxx' })
    expect(result.severity).toBe('high')
    expect(result.warning).toBeDefined()
    expect(result.warning!.class).toBe('informational')
    expect(result.warning!.message).toContain('GHSA-zzzz-yyyy-xxxx')
  })

  it('escalates unknown label value to high and emits warning', () => {
    const result = mapSeverity({ label: 'NONE', advisoryId: 'MAL-0001-0001' })
    expect(result.severity).toBe('high')
    expect(result.warning).toBeDefined()
    expect(result.warning!.class).toBe('informational')
    expect(result.warning!.message).toContain('MAL-0001-0001')
  })
})

describe('resolveAdvisorySeverity — malware override', () => {
  it('forces mal advisories to critical regardless of a non-critical label', () => {
    const result = resolveAdvisorySeverity('mal', 'low', 'MAL-0001-0001')
    expect(result.severity).toBe('critical')
  })

  it('forces mal advisories to critical even when the label is missing', () => {
    const result = resolveAdvisorySeverity('mal', undefined, 'MAL-0002-0002')
    expect(result.severity).toBe('critical')
  })

  it('does not emit a misleading "defaulting to high" warning for a mal advisory with no label', () => {
    // The mal rule sets severity to critical, so the label-default warning (which says the
    // advisory was treated as 'high') would be factually wrong. It must be suppressed.
    const result = resolveAdvisorySeverity('mal', undefined, 'MAL-0003-0003')
    expect(result.severity).toBe('critical')
    expect(result.warning).toBeUndefined()
  })

  it('passes a cve advisory severity through unchanged', () => {
    const result = resolveAdvisorySeverity('cve', 'moderate', 'CVE-2024-0001')
    expect(result.severity).toBe('moderate')
    expect(result.warning).toBeUndefined()
  })

  it('preserves the fail-safe high + warning for a cve with an unknown label', () => {
    const result = resolveAdvisorySeverity('cve', 'bogus', 'CVE-2024-0002')
    expect(result.severity).toBe('high')
    expect(result.warning).toBeDefined()
    expect(result.warning!.class).toBe('informational')
  })
})
