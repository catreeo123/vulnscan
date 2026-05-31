import { it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { installSkill } from './skill-installer.js'

let tmp: string
let sourceFile: string
let claudeDir: string

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'vulnscan-skill-test-'))
  sourceFile = join(tmp, 'SKILL.md')
  writeFileSync(sourceFile, '# vulnscan skill content')
  claudeDir = join(tmp, '.claude')
})

afterEach(() => rm(tmp, { recursive: true, force: true }))

it('copies SKILL.md to ~/.claude/skills/vulnscan/ and prints installed message', () => {
  mkdirSync(claudeDir, { recursive: true })

  const written: string[] = []
  const origWrite = process.stdout.write.bind(process.stdout)
  ;(process.stdout as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }

  installSkill({ claudeDir, sourcePath: sourceFile })

  ;(process.stdout as any).write = origWrite

  const dest = join(claudeDir, 'skills', 'vulnscan', 'SKILL.md')
  expect(existsSync(dest)).toBe(true)
  expect(readFileSync(dest, 'utf8')).toBe('# vulnscan skill content')
  expect(written.join('')).toMatch(/skill installed/)
  expect(written.join('')).toContain(dest)
})

it('prints "skill updated" when already installed', () => {
  const skillDir = join(claudeDir, 'skills', 'vulnscan')
  mkdirSync(skillDir, { recursive: true })
  writeFileSync(join(skillDir, 'SKILL.md'), '# old content')

  const written: string[] = []
  const origWrite = process.stdout.write.bind(process.stdout)
  ;(process.stdout as any).write = (chunk: unknown) => { written.push(String(chunk)); return true }

  installSkill({ claudeDir, sourcePath: sourceFile })

  ;(process.stdout as any).write = origWrite

  expect(written.join('')).toMatch(/skill updated/)
  expect(readFileSync(join(skillDir, 'SKILL.md'), 'utf8')).toBe('# vulnscan skill content')
})

it('warns on stderr when ~/.claude/ did not exist before install', () => {
  // claudeDir does NOT exist yet
  const stderrWrites: string[] = []
  const origWrite = process.stderr.write.bind(process.stderr)
  ;(process.stderr as any).write = (chunk: unknown) => { stderrWrites.push(String(chunk)); return true }
  const stdoutWrites: string[] = []
  const origStdout = process.stdout.write.bind(process.stdout)
  ;(process.stdout as any).write = (chunk: unknown) => { stdoutWrites.push(String(chunk)); return true }

  installSkill({ claudeDir, sourcePath: sourceFile })

  ;(process.stderr as any).write = origWrite
  ;(process.stdout as any).write = origStdout

  expect(existsSync(join(claudeDir, 'skills', 'vulnscan', 'SKILL.md'))).toBe(true)
  expect(stderrWrites.join('')).toMatch(/claude code/i)
})
