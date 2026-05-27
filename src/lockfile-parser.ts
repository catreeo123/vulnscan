import type { Dep } from './types.js'
import { buildAncestryMap } from './ancestry.js'
import { incomplete } from './warnings.js'
import type { ScanWarning } from './warnings.js'

export type { Dep }

type PackageEntry = {
  version?: string
  resolved?: string
  name?: string
}

export function parseLockfile(
  content: string,
  packageJsonContent?: string,
): { deps: Dep[]; warnings: ScanWarning[] } {
  let lock: { packages: Record<string, PackageEntry> }
  try {
    lock = JSON.parse(content) as { packages: Record<string, PackageEntry> }
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

  for (const [path, pkg] of Object.entries(lock.packages)) {
    if (path === '') continue
    if (!pkg.version) continue

    const parts = path.split('node_modules/')
    const name = parts[parts.length - 1]

    if (pkg.name !== undefined && pkg.name !== name) {
      warnings.push(incomplete(`${name}: npm alias to '${pkg.name}' skipped (alias version ranges may not match advisories)`))
      continue
    }

    if (pkg.resolved?.startsWith('git+') || pkg.resolved?.startsWith('git://')) {
      warnings.push(incomplete(`${name}: git-sourced dep skipped (cannot check version range)`))
      continue
    }

    const dep: Dep = { name, version: pkg.version }
    const via = ancestryMap.get(name)
    if (via !== undefined) dep.via = via

    deps.push(dep)
  }

  return { deps, warnings }
}
