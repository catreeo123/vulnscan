import type { Dep } from './types.js'
import { buildAncestryMap } from './ancestry.js'
import { incomplete } from './warnings.js'
import type { ScanWarning } from './warnings.js'
import { resolveEntry } from './lockfile-resolver.js'
import type { PackageEntry } from './lockfile-resolver.js'

export type { Dep }

type LockfileRoot = {
  packages: Record<string, PackageEntry & { workspaces?: string[] }>
}

export function parseLockfile(
  content: string,
  packageJsonContent?: string,
): { deps: Dep[]; warnings: ScanWarning[] } {
  let lock: LockfileRoot
  try {
    lock = JSON.parse(content) as LockfileRoot
  } catch (e) {
    throw new Error('package-lock.json is not valid JSON: ' + (e as Error).message)
  }
  const deps: Dep[] = []
  const warnings: ScanWarning[] = []

  let packageJson: Record<string, unknown> = {}
  if (packageJsonContent) {
    try {
      packageJson = JSON.parse(packageJsonContent) as Record<string, unknown>
    } catch {
      warnings.push(incomplete('package.json parse failed — ancestry tracking disabled'))
    }
  }

  const ancestryMap = buildAncestryMap(
    lock as unknown as Record<string, unknown>,
    packageJson,
  )

  if (!lock.packages) {
    return { deps: [], warnings: [incomplete('package-lock.json v1 not supported — run npm install to regenerate as v2/v3')] }
  }

  const rootWorkspaces: string[] = lock.packages['']?.workspaces ?? []

  for (const [path, pkg] of Object.entries(lock.packages)) {
    if (path === '') continue

    const { dep, warning } = resolveEntry(path, pkg, rootWorkspaces)

    if (warning) warnings.push(warning)

    if (dep) {
      // Apply ancestry only for non-alias, non-workspace deps (those that don't already have via set)
      if (dep.via === undefined && !dep.local) {
        const via = ancestryMap.get(dep.name)
        if (via !== undefined) dep.via = via
      }
      deps.push(dep)
    }
  }

  return { deps, warnings }
}
