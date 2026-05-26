export function scrubSecrets(msg: string): string {
  return msg
    .replace(/Bearer\s+[A-Za-z0-9_.\-]+/gi, 'Bearer [REDACTED]')
    .replace(/(?:^|[^A-Za-z])(?:token|authorization)[:\s=]+[A-Za-z0-9_.\-]+/gi, (m) =>
      m.replace(/[A-Za-z0-9_.\-]+$/, '[REDACTED]'),
    )
    .replace(/ghp_[A-Za-z0-9]{20,}/g, 'ghp_[REDACTED]')
    .replace(/gho_[A-Za-z0-9]{20,}/g, 'gho_[REDACTED]')
    .replace(/ghs_[A-Za-z0-9]{20,}/g, 'ghs_[REDACTED]')
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, 'github_pat_[REDACTED]')
}
