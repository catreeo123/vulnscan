#!/usr/bin/env node
import semver from 'semver'
import { resolve } from 'node:path'
import { existsSync, readFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { openStore } from '../store/advisory-store-sqlite.js'
import { runSync } from '../sync/sync-orchestrator.js'
import { loadConfig } from '../core/config.js'
import { renderGrouped, renderJson } from '../output/output-renderer.js'
import { runScan, checkPackage } from './scanner.js'
import { parseArgs } from './cli-args.js'
import { scrubSecrets } from '../core/secrets.js'
import { maybeBootstrap } from '../sync/bootstrap.js'
import { hasIncomplete } from '../core/warnings.js'
import { computeExitCode, resolveFailOn } from '../core/failure-threshold.js'

export async function run(argv: string[]): Promise<number> {
  const parsed = parseArgs(argv)

  if (parsed.command === 'version') {
    const { createRequire } = await import('node:module')
    const require = createRequire(import.meta.url)
    const { version } = require('../../package.json') as { version: string }
    process.stdout.write(version + '\n')
    return 0
  }

  if (parsed.command === 'help') {
    process.stdout.write(renderHelp(parsed.topic))
    return 0
  }

  if (parsed.command === 'update') {
    const store = openStore()
    try {
      const warnings = await runSync(store)
      // Fail safe: an incomplete sync must not look like a clean refresh, so CI
      // (default `bash -e`) skips publishing and keeps the last-good db-latest.
      return hasIncomplete(warnings) ? 2 : 0
    } finally {
      safeClose(store)
    }
  }

  if (parsed.command === 'check') {
    const pkgArg = parsed.target
    const lastAt = pkgArg.lastIndexOf('@')
    // lastAt <= 0 covers both "no @" (-1) and a leading @ (0) — e.g. an unversioned
    // scoped package "@scope/pkg", which would otherwise parse to an empty name and
    // silently report clean.
    if (lastAt <= 0) {
      process.stderr.write('Usage: vulnscan check <package@version>\n')
      return 1
    }
    const name = pkgArg.slice(0, lastAt)
    const version = pkgArg.slice(lastAt + 1)
    // An empty or unparseable version makes matchAffected's semver.satisfies() return false
    // for every advisory, so a vulnerable package would falsely report clean (exit 0) — the
    // worst failure mode for a security tool. Reject it like a missing argument.
    if (!semver.valid(version)) {
      process.stderr.write('Usage: vulnscan check <package@version>\n')
      return 1
    }

    const config = loadConfig(parsed.dir ?? '.')
    await maybeBootstrap()
    const store = openStore()
    try {
      const result = await checkPackage({ name, version, store, config, noSync: parsed.noSync })

      if (parsed.format === 'json') {
        process.stdout.write(renderJson(result.findings, result.warnings) + '\n')
      } else {
        process.stderr.write(`Checked ${pkgArg} against ${result.advisoryCount} advisories\n`)
        process.stdout.write(renderGrouped(result.findings, result.warnings) + '\n')
      }

      return computeExitCode(result.findings, result.warnings, resolveFailOn(parsed.failOn, config))
    } finally {
      safeClose(store)
    }
  }

  if (parsed.command === 'scan') {
    const projectDir = resolve(parsed.projectDir)
    const lockfilePath = resolve(projectDir, 'package-lock.json')
    if (!existsSync(lockfilePath)) {
      process.stderr.write(`Error: package-lock.json not found at ${lockfilePath}\n`)
      return 1
    }
    await maybeBootstrap()
    const store = openStore()
    try {
      const config = loadConfig(projectDir)
      const lockfileContent = readFileSync(lockfilePath, 'utf8')
      const packageJsonPath = resolve(projectDir, 'package.json')
      const packageJsonContent = existsSync(packageJsonPath) ? readFileSync(packageJsonPath, 'utf8') : undefined

      const result = await runScan({ lockfileContent, packageJsonContent, store, config, noSync: parsed.noSync })

      if (parsed.format === 'json') {
        process.stdout.write(renderJson(result.findings, result.warnings) + '\n')
      } else {
        process.stderr.write(`Checked ${result.depCount} packages against ${result.advisoryCount} advisories\n`)
        process.stdout.write(renderGrouped(result.findings, result.warnings) + '\n')
      }

      return computeExitCode(result.findings, result.warnings, resolveFailOn(parsed.failOn, config))
    } finally {
      safeClose(store)
    }
  }

  if (parsed.command === 'skill-install') {
    const { installSkill } = await import('./skill-installer.js')
    installSkill()
    return 0
  }

  const raw = parsed.command === 'unknown' ? (parsed.raw ?? '') : ''
  process.stderr.write(`Unknown command: ${raw}\nUsage: vulnscan [scan|check|update|skill] [options]\n`)
  return 1
}

function renderHelp(topic?: 'scan' | 'check' | 'update' | 'skill'): string {
  if (topic === 'scan') {
    return `vulnscan scan — scan a project's package-lock.json for known vulnerabilities

Usage:
  vulnscan scan [<dir>] [--format json|table] [--fail-on critical,high,...] [--offline]
  vulnscan [<dir>]                     (scan is the default command)

Options:
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --offline, --no-sync  Skip advisory database sync (use existing local data)
  --help, -h         Show this message

Exit codes (priority: 2 > 1 > 0):
  0   Clean — no findings at or above the fail-on threshold, and no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold (no incomplete warnings)
  2   Incomplete — scan could not cover all packages (e.g. git-sourced deps, v1 lockfile);
      exit 2 takes priority over exit 1 because the missing packages may have undetected findings
`
  }
  if (topic === 'check') {
    return `vulnscan check — check a single package@version against the advisory database

Usage:
  vulnscan check <pkg@version> [--dir <path>] [--format json|table] [--fail-on ...] [--offline]

Options:
  --dir <path>       Directory for .vulnscanrc lookup (default: current directory)
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --offline, --no-sync  Skip advisory database sync (use existing local data)
  --help, -h         Show this message

Exit codes (priority: 2 > 1 > 0):
  0   Clean — no findings at or above the fail-on threshold, and no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold (no incomplete warnings)
  2   Incomplete — check could not fully cover the package (e.g. incomplete advisory sync);
      exit 2 takes priority over exit 1 because the missing coverage may hide worse findings
`
  }
  if (topic === 'update') {
    return `vulnscan update — force a full re-sync of the local advisory database

Usage:
  vulnscan update

Environment:
  VULNSCAN_DB_PATH   Override the SQLite path (default: ~/.vulnscan/db.sqlite)
  GITHUB_TOKEN       Auth for the GitHub Advisory API (without it, 60 req/hr)

Options:
  --help, -h         Show this message
`
  }
  if (topic === 'skill') {
    return `vulnscan skill — manage the /vulnscan Claude Code skill

Usage:
  vulnscan skill install         Copy SKILL.md to ~/.claude/skills/vulnscan/

Options:
  --help, -h         Show this message
`
  }
  return `vulnscan — npm dependency vulnerability scanner

Usage:
  vulnscan [scan] [<dir>] [--format json|table] [--fail-on critical,high,...] [--offline]
  vulnscan check <pkg@version> [--dir <path>] [--format json|table] [--fail-on ...] [--offline]
  vulnscan update
  vulnscan skill install         Register the /vulnscan Claude Code skill
  vulnscan <command> --help     Show usage for a specific subcommand
  vulnscan --help

Options:
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --dir <path>       (check only) directory for .vulnscanrc lookup
  --offline, --no-sync  Skip advisory database sync (use existing local data)
  --help, -h         Show this message

Exit codes (priority: 2 > 1 > 0):
  0   Clean — no findings at or above the fail-on threshold, and no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold (no incomplete warnings)
  2   Incomplete — scan could not cover all packages; exit 2 takes priority over exit 1
      because the missing packages may have undetected findings
`
}

export function safeClose(db: { close(): void }): void {
  try {
    db.close()
  } catch (err) {
    process.stderr.write(`Warning: db.close failed: ${(err as Error).message}\n`)
  }
}

// Only dispatch when executed as the entry point (bin / `node dist/cli.js` / `tsx src/cli.ts`),
// not when imported by tests or tooling — importing must not open the DB, hit the network,
// or mutate process.exitCode. realpath handles the symlinked global bin.
function isEntryPoint(): boolean {
  const entry = process.argv[1]
  if (!entry) return false
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
}

if (isEntryPoint()) {
  run(process.argv.slice(2))
    .then((code) => { process.exitCode = code })
    .catch((err: Error) => {
      process.stderr.write(`Error: ${scrubSecrets(err.message)}\n`)
      process.exitCode = 1
    })
}
