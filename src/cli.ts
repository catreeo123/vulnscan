#!/usr/bin/env node
import { resolve } from 'node:path'
import { existsSync, readFileSync } from 'node:fs'
import { openStore } from './advisory-store-sqlite.js'
import { runSync } from './sync-orchestrator.js'
import { loadConfig, validateFailOn } from './config.js'
import { renderGrouped, renderJson } from './output-renderer.js'
import { runScan, checkPackage } from './scanner.js'
import { parseArgs } from './cli-args.js'
import { scrubSecrets } from './secrets.js'
import { maybeBootstrap } from './bootstrap.js'
import { hasIncomplete } from './warnings.js'
import type { Severity, Finding } from './types.js'
import type { ScanWarning } from './warnings.js'

// M3: parseArgs is now called inside main(), not at module scope.

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2)) // M3 fix

  if (parsed.command === 'help') {
    process.stdout.write(renderHelp(parsed.topic))
    return
  }

  if (parsed.command === 'update') {
    const store = openStore()
    try { // B2 fix
      await runSync(store)
    } finally {
      safeClose(store)
    }
    return
  }

  if (parsed.command === 'check') {
    const pkgArg = parsed.target
    if (!pkgArg.includes('@')) {
      process.stderr.write('Usage: vulnscan check <package@version>\n')
      process.exit(1)
    }
    const lastAt = pkgArg.lastIndexOf('@')
    const name = pkgArg.slice(0, lastAt)
    const version = pkgArg.slice(lastAt + 1)

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

      // M1 fix: use exitCode + return instead of process.exit after stdout writes
      process.exitCode = computeExitCode(result.findings, result.warnings, getFailOn(parsed.failOn, parsed.dir ?? '.'))
    } finally {
      safeClose(store)
    }
    return
  }

  if (parsed.command === 'scan') {
    const projectDir = resolve(parsed.projectDir)
    const lockfilePath = resolve(projectDir, 'package-lock.json')
    if (!existsSync(lockfilePath)) {
      process.stderr.write(`Error: package-lock.json not found at ${lockfilePath}\n`)
      process.exit(1)
    }
    await maybeBootstrap()
    const store = openStore()
    try { // B2 fix
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

      const failOn = getFailOn(parsed.failOn, projectDir)
      // M1 fix: use exitCode + return instead of process.exit after stdout writes
      process.exitCode = computeExitCode(result.findings, result.warnings, failOn)
    } finally {
      safeClose(store)
    }
    return
  }

  process.stderr.write(`Unknown command: ${parsed.raw ?? ''}\nUsage: vulnscan [scan|check|update] [options]\n`)
  process.exit(1)
}

function renderHelp(topic?: 'scan' | 'check' | 'update'): string {
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

Exit codes:
  0   Clean — no findings at or above the fail-on threshold, no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold
  2   Incomplete — scan could not cover all packages (e.g. git-sourced deps, v1 lockfile)
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

Exit codes:
  0   Clean — no findings at or above the fail-on threshold, no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold
  2   Incomplete — check could not fully cover the package (e.g. incomplete advisory sync)
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
  return `vulnscan — npm dependency vulnerability scanner

Usage:
  vulnscan [scan] [<dir>] [--format json|table] [--fail-on critical,high,...] [--offline]
  vulnscan check <pkg@version> [--dir <path>] [--format json|table] [--fail-on ...] [--offline]
  vulnscan update
  vulnscan <command> --help     Show usage for a specific subcommand
  vulnscan --help

Options:
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --dir <path>       (check only) directory for .vulnscanrc lookup
  --offline, --no-sync  Skip advisory database sync (use existing local data)
  --help, -h         Show this message

Exit codes:
  0   Clean — no findings at or above the fail-on threshold, no incomplete warnings
  1   Findings — one or more findings meet the fail-on severity threshold
  2   Incomplete — scan could not cover all packages; check pipelines accordingly
`
}

export function safeClose(db: { close(): void }): void {
  try {
    db.close()
  } catch (err) {
    process.stderr.write(`Warning: db.close failed: ${(err as Error).message}\n`)
  }
}

function getFailOn(failOnArg: string | null, projectDir = '.'): Severity[] {
  if (failOnArg) return validateFailOn(failOnArg.split(',')) // M2 fix: validate instead of cast
  const config = loadConfig(projectDir)
  return config.failOn
}

function shouldFail(findings: Finding[], failOn: Severity[]): boolean {
  return findings.some((f) => failOn.includes(f.advisory.severity))
}

/**
 * Exit code matrix:
 *   1 — findings ≥ failOn severity (overrides 2)
 *   2 — no qualifying findings, but at least one incomplete warning
 *   0 — clean
 */
function computeExitCode(findings: Finding[], warnings: ScanWarning[], failOn: Severity[]): number {
  if (shouldFail(findings, failOn)) return 1
  if (hasIncomplete(warnings)) return 2
  return 0
}

main().catch((err) => {
  process.stderr.write(`Error: ${scrubSecrets((err as Error).message)}\n`)
  process.exit(1)
})
