import type { Dep } from './types.js'
import { incomplete, informational } from './warnings.js'
import type { ScanWarning } from './warnings.js'

export type PackageEntry = {
  version?: string
  resolved?: string
  name?: string
  link?: boolean
}

export type ResolveResult = {
  dep?: Dep
  warning?: ScanWarning
}

/**
 * Simple glob matcher supporting only `*` (matches one path segment) and `**` (matches any segments).
 * Sufficient for npm workspace glob patterns like "packages/*".
 */
function matchesGlob(pattern: string, subject: string): boolean {
  // Escape regex special chars except * which we'll handle
  const regexStr = pattern
    .split('**')
    .map((part) =>
      part
        .split('*')
        .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('[^/]+'),
    )
    .join('.*')
  return new RegExp(`^${regexStr}$`).test(subject)
}

/**
 * Resolve a single lockfile package entry to a Dep and/or ScanWarning.
 *
 * @param path - The lockfile path key (e.g. "node_modules/lodash" or "packages/frontend")
 * @param pkg  - The package entry object
 * @param rootWorkspaces - workspace glob patterns from lock.packages['']?.workspaces
 */
export function resolveEntry(
  path: string,
  pkg: PackageEntry,
  rootWorkspaces: string[] = [],
): ResolveResult {
  const isUnderNodeModules = path.includes('node_modules/')

  // git-source dep — no dep, incomplete warning
  if (
    pkg.resolved?.startsWith('git+') ||
    pkg.resolved?.startsWith('git://') ||
    pkg.resolved?.startsWith('github:') ||
    pkg.resolved?.startsWith('bitbucket:') ||
    pkg.resolved?.startsWith('gitlab:')
  ) {
    const parts = path.split('node_modules/')
    const name = parts[parts.length - 1]
    return { warning: incomplete(`${name}: git-sourced dep skipped (cannot check version range)`) }
  }

  // npm workspace: entry has link:true, OR path matches a root workspace glob
  const isWorkspaceByLink = pkg.link === true
  const isWorkspaceByGlob =
    !isUnderNodeModules &&
    rootWorkspaces.some((glob) => matchesGlob(glob, path))

  if (isWorkspaceByLink || isWorkspaceByGlob) {
    const name = pkg.name ?? path.split('/').pop() ?? path
    const version = pkg.version ?? '0.0.0'
    return { dep: { name, version, local: true } }
  }

  // npm alias: name field differs from path-derived name, AND under node_modules
  if (isUnderNodeModules && pkg.name !== undefined) {
    const parts = path.split('node_modules/')
    const aliasKey = parts[parts.length - 1]
    if (pkg.name !== aliasKey) {
      // A missing/empty version can't be range-checked. Fabricating '0.0.0' (or keeping '')
      // would make the aliased package match no advisory and silently report clean (false
      // negative) behind only an informational warning. Surface as incomplete (exit 2),
      // mirroring the plain-dep empty-version guard below.
      if (pkg.version === undefined || pkg.version.trim() === '') {
        return {
          warning: incomplete(
            `${aliasKey}: npm alias to '${pkg.name}' has no resolvable version (cannot check version range)`,
          ),
        }
      }
      return {
        dep: { name: pkg.name, version: pkg.version, via: aliasKey },
        warning: informational(
          `${aliasKey}: npm alias to '${pkg.name}' — advisories checked against target package`,
        ),
      }
    }
  }

  // Plain transitive dep
  if (isUnderNodeModules && pkg.version !== undefined) {
    const parts = path.split('node_modules/')
    const name = parts[parts.length - 1]
    // An empty/whitespace version is not undefined, so it would otherwise become a Dep with
    // version '' — which matchAffected can never satisfy, silently reporting a vulnerable
    // package as clean (exit 0). Surface it as incomplete (exit 2) instead, like a git dep.
    if (pkg.version.trim() === '') {
      return { warning: incomplete(`${name}: lockfile entry has an empty version (cannot check version range)`) }
    }
    return { dep: { name, version: pkg.version } }
  }

  // No version and not a known special case — skip silently
  return {}
}
