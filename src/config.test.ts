import { describe, it, expect, afterEach, vi } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadConfig } from './config.js'

let tmpDir: string

afterEach(() => {
  if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

function makeTmpDir() {
  tmpDir = mkdtempSync(join(tmpdir(), 'vulnscan-config-test-'))
  return tmpDir
}

describe('loadConfig', () => {
  it('rejects invalid severities and falls back to DEFAULTS, warning on stderr', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ failOn: ['CRITICAL', 'bogus'] }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.failOn).toEqual(['critical', 'high'])
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('CRITICAL'))
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('bogus'))
  })

  it('warns and falls back when .vulnscanrc is malformed JSON', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), '{ "failOn": ["low"], }') // trailing comma → invalid JSON

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('.vulnscanrc'))
    expect(config.failOn).toEqual(['critical', 'high'])
  })

  it('does not warn when no .vulnscanrc exists (missing file is silent)', () => {
    const dir = makeTmpDir()

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    loadConfig(dir)

    expect(stderrSpy).not.toHaveBeenCalled()
  })

  it('accepts valid severities unchanged with no warning', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ failOn: ['high', 'low'] }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.failOn).toEqual(['high', 'low'])
    expect(stderrSpy).not.toHaveBeenCalled()
  })

  it('returns DEFAULTS when no .vulnscanrc exists', () => {
    const dir = makeTmpDir()
    // no .vulnscanrc written

    const config = loadConfig(dir)

    expect(config.failOn).toEqual(['critical', 'high'])
    expect(config.stalenessHours).toBe(24)
  })

  it('stalenessHours "never" emits warning and uses default', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ stalenessHours: 'never' }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.stalenessHours).toBe(24)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('stalenessHours is invalid'))
  })

  it('stalenessHours -1 emits warning and uses default', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ stalenessHours: -1 }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.stalenessHours).toBe(24)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('stalenessHours is invalid'))
  })

  it('stalenessHours 0 emits warning and uses default', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ stalenessHours: 0 }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.stalenessHours).toBe(24)
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('stalenessHours is invalid'))
  })

  it('stalenessHours 48 (valid) uses 48 with no warning', () => {
    const dir = makeTmpDir()
    writeFileSync(join(dir, '.vulnscanrc'), JSON.stringify({ stalenessHours: 48 }))

    const stderrSpy = vi.spyOn(process.stderr, 'write')
    const config = loadConfig(dir)

    expect(config.stalenessHours).toBe(48)
    expect(stderrSpy).not.toHaveBeenCalled()
  })
})
