export type Dep = { name: string; version: string; via?: string }

export type Severity = 'critical' | 'high' | 'moderate' | 'low'

export type SemverRange = {
  introduced?: string
  fixed?: string
  lastAffected?: string
  rawRange?: string
}

export type Advisory = {
  id: string
  canonicalId: string
  type: 'cve' | 'mal'
  packageName: string
  ranges: SemverRange[]
  severity: Severity
  title: string
  url: string
}

export type Finding = {
  name: string
  version: string
  via?: string
  advisory: Advisory
}
