/** Scheduled send's limits (Proton's): from a minute to 90 days ahead. */
export const SCHEDULE_MIN_MS = 60_000
export const SCHEDULE_MAX_MS = 90 * 24 * 60 * 60_000

/** At 8:00 on `date`'s day, local time. */
function morning(date: Date): Date {
  const at = new Date(date)
  at.setHours(8, 0, 0, 0)
  return at
}

/**
 * Proton's quick choices: tomorrow morning and next Monday morning (8:00,
 * local), Monday left out when it is tomorrow.
 */
export function scheduleSuggestions(now = new Date()): { kind: 'tomorrow' | 'monday'; at: Date }[] {
  const tomorrow = new Date(now)
  tomorrow.setDate(now.getDate() + 1)
  const monday = new Date(now)
  monday.setDate(now.getDate() + (((8 - now.getDay()) % 7) || 7))
  const out: { kind: 'tomorrow' | 'monday'; at: Date }[] = [{ kind: 'tomorrow', at: morning(tomorrow) }]
  if (monday.toDateString() !== tomorrow.toDateString()) out.push({ kind: 'monday', at: morning(monday) })
  return out
}

/** Whether `at` may be chosen. */
export function schedulable(at: Date, now = new Date()): boolean {
  const ahead = at.getTime() - now.getTime()
  return Number.isFinite(ahead) && ahead >= SCHEDULE_MIN_MS && ahead <= SCHEDULE_MAX_MS
}
