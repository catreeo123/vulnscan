export type ScanWarning = {
  class: 'incomplete' | 'informational'
  message: string
}

export function incomplete(message: string): ScanWarning {
  return { class: 'incomplete', message }
}

export function informational(message: string): ScanWarning {
  return { class: 'informational', message }
}

export function hasIncomplete(warnings: ScanWarning[]): boolean {
  return warnings.some((w) => w.class === 'incomplete')
}
