import { mkdirSync, copyFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'

const DEFAULT_SOURCE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'skill', 'SKILL.md')

export function installSkill(opts?: { claudeDir?: string; sourcePath?: string }): void {
  const claudeDir = opts?.claudeDir ?? join(homedir(), '.claude')
  const sourcePath = opts?.sourcePath ?? DEFAULT_SOURCE
  const skillDir = join(claudeDir, 'skills', 'vulnscan')
  const dest = join(skillDir, 'SKILL.md')

  const claudeMissing = !existsSync(claudeDir)
  const alreadyInstalled = existsSync(dest)

  mkdirSync(skillDir, { recursive: true })
  copyFileSync(sourcePath, dest)

  if (claudeMissing) {
    process.stderr.write(`note: ${claudeDir} created — install Claude Code to use this skill\n`)
  }

  const verb = alreadyInstalled ? 'updated' : 'installed'
  process.stdout.write(`skill ${verb} -> ${dest}\n`)
}
