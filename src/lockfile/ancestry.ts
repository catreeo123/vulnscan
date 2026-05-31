type PackageEntry = {
  dependencies?: Record<string, string>
  [key: string]: unknown
}

type LockfileV2 = {
  packages: Record<string, PackageEntry>
  [key: string]: unknown
}

/**
 * Build a map of { packageName → rootDepName } for transitive deps.
 * Root deps themselves are absent from the map.
 * Uses BFS in declaration order; first BFS to reach a package path wins.
 * Returns empty map for v1 lockfiles (no `packages` key).
 *
 * forwardDeps is keyed by full lockfile path (e.g. "node_modules/foo/node_modules/bar")
 * so nested packages don't corrupt hoisted packages' dep lists.
 * Dep name resolution follows npm's algorithm: nearest node_modules ancestor wins.
 */
export function buildAncestryMap(
  lockfileJson: Record<string, unknown>,
  packageJson: Record<string, unknown>,
): Map<string, string> {
  if (!lockfileJson.packages) return new Map()

  const lock = lockfileJson as LockfileV2
  const packages = lock.packages

  // Build forward dep map: fullPath → dep names
  const forwardDeps = new Map<string, string[]>()
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '') continue
    const depNames = entry.dependencies ? Object.keys(entry.dependencies) : []
    forwardDeps.set(path, depNames)
  }

  // Resolve a dep name from parentPath using npm resolution:
  // walk up node_modules ancestors, deepest match wins.
  function resolveDepPath(parentPath: string, depName: string): string | undefined {
    let current = parentPath
    while (current) {
      const candidate = `${current}/node_modules/${depName}`
      if (forwardDeps.has(candidate)) return candidate
      const idx = current.lastIndexOf('/node_modules/')
      if (idx < 0) break
      current = current.slice(0, idx)
    }
    const hoisted = `node_modules/${depName}`
    return forwardDeps.has(hoisted) ? hoisted : undefined
  }

  function shortName(fullPath: string): string {
    const parts = fullPath.split('node_modules/')
    return parts[parts.length - 1]
  }

  // Collect root deps in declaration order: dependencies → devDependencies → optionalDependencies
  const rootDeps: string[] = []
  const rootSet = new Set<string>()
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const block = packageJson[section]
    if (block && typeof block === 'object') {
      for (const name of Object.keys(block as Record<string, unknown>)) {
        if (!rootSet.has(name)) {
          rootSet.add(name)
          rootDeps.push(name)
        }
      }
    }
  }

  // BFS from each root dep's full path; first to claim a path wins
  const ancestryMap = new Map<string, string>()
  const visitedPaths = new Set<string>()

  const queue: Array<[string, string]> = [] // [fullPath, rootDepName]

  for (const rootName of rootDeps) {
    const rootPath = `node_modules/${rootName}`
    visitedPaths.add(rootPath)
    const depNames = forwardDeps.get(rootPath) ?? []
    for (const depName of depNames) {
      const depPath = resolveDepPath(rootPath, depName)
      if (depPath && !visitedPaths.has(depPath)) {
        visitedPaths.add(depPath)
        ancestryMap.set(shortName(depPath), rootName)
        queue.push([depPath, rootName])
      }
    }
  }

  while (queue.length > 0) {
    const [pkgPath, root] = queue.shift()!
    const depNames = forwardDeps.get(pkgPath) ?? []
    for (const depName of depNames) {
      const depPath = resolveDepPath(pkgPath, depName)
      if (depPath && !visitedPaths.has(depPath)) {
        visitedPaths.add(depPath)
        ancestryMap.set(shortName(depPath), root)
        queue.push([depPath, root])
      }
    }
  }

  return ancestryMap
}
