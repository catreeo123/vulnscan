#!/usr/bin/env node
import { resolve } from 'node:path'
import { existsSync, readFileSync } from 'node:fs'
import { openDb } from './local-db.js'
import { runSync } from './sync-orchestrator.js'
import { loadConfig, validateFailOn } from './config.js'
import { renderGrouped, renderJson } from './output-renderer.js'
import { runScan, checkPackage } from './scanner.js'
import { parseArgs } from './cli-args.js'
import { scrubSecrets } from './secrets.js'
import type { Severity, Finding } from './types.js'

// M3: parseArgs is now called inside main(), not at module scope.

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2)) // M3 fix

  if (parsed.command === 'help') {
    process.stdout.write(renderHelp(parsed.topic))
    return
  }

  if (parsed.command === 'update') {
    const db = openDb()
    try { // B2 fix
      await runSync(db)
    } finally {
      safeClose(db)
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
    const db = openDb()
    try {
      const result = await checkPackage({ name, version, db, config })

      if (parsed.format === 'json') {
        process.stdout.write(renderJson(result.findings, []) + '\n')
      } else {
        process.stderr.write(`Checked ${pkgArg} against ${result.advisoryCount} advisories\n`)
        process.stdout.write(renderGrouped(result.findings, []) + '\n')
      }

      // M1 fix: use exitCode + return instead of process.exit after stdout writes
      process.exitCode = shouldFail(result.findings, getFailOn(parsed.failOn, parsed.dir ?? '.')) ? 1 : 0
    } finally {
      safeClose(db)
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
    const db = openDb()
    try { // B2 fix
      const config = loadConfig(projectDir)
      const lockfileContent = readFileSync(lockfilePath, 'utf8')
      const packageJsonPath = resolve(projectDir, 'package.json')
      const packageJsonContent = existsSync(packageJsonPath) ? readFileSync(packageJsonPath, 'utf8') : undefined

      const result = await runScan({ lockfileContent, packageJsonContent, db, config })

      if (parsed.format === 'json') {
        process.stdout.write(renderJson(result.findings, result.warnings) + '\n')
      } else {
        process.stderr.write(`Checked ${result.depCount} packages against ${result.advisoryCount} advisories\n`)
        process.stdout.write(renderGrouped(result.findings, result.warnings) + '\n')
      }

      const failOn = getFailOn(parsed.failOn, projectDir)
      // M1 fix: use exitCode + return instead of process.exit after stdout writes
      process.exitCode = shouldFail(result.findings, failOn) ? 1 : 0
    } finally {
      safeClose(db)
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
  vulnscan scan [<dir>] [--format json|table] [--fail-on critical,high,...]
  vulnscan [<dir>]                     (scan is the default command)

Options:
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --help, -h         Show this message
`
  }
  if (topic === 'check') {
    return `vulnscan check — check a single package@version against the advisory database

Usage:
  vulnscan check <pkg@version> [--dir <path>] [--format json|table] [--fail-on ...]

Options:
  --dir <path>       Directory for .vulnscanrc lookup (default: current directory)
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --help, -h         Show this message
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
  vulnscan [scan] [<dir>] [--format json|table] [--fail-on critical,high,...]
  vulnscan check <pkg@version> [--dir <path>] [--format json|table] [--fail-on ...]
  vulnscan update
  vulnscan <command> --help     Show usage for a specific subcommand
  vulnscan --help

Options:
  --format <fmt>     Output format: 'table' (default) or 'json'
  --fail-on <csv>    Comma-separated severities that cause exit 1 (overrides .vulnscanrc)
  --dir <path>       (check only) directory for .vulnscanrc lookup
  --help, -h         Show this message
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

main().catch((err) => {
  process.stderr.write(`Error: ${scrubSecrets((err as Error).message)}\n`)
  process.exit(1)
})
