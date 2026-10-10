/**
 * Timestamp formatting.
 *
 * The server pins every timestamp to RFC 3339 (`time`'s default serde
 * representation is a positional array that `new Date()` cannot read), so a
 * plain `new Date(value)` is safe here — but only because a Rust test enforces
 * it. `parseInstant` still returns `null` on anything unparseable rather than
 * rendering "Invalid Date" into the table.
 */

// Intl formatters are costly to make (a list of 300 files made 600 of them
// per render) and cheap to reuse: kept per locale and options.
const formatters = new Map<string, Intl.DateTimeFormat | Intl.NumberFormat | Intl.RelativeTimeFormat>()

function cached<T extends Intl.DateTimeFormat | Intl.NumberFormat | Intl.RelativeTimeFormat>(key: string, make: () => T): T {
  let formatter = formatters.get(key) as T | undefined
  if (!formatter) {
    formatter = make()
    formatters.set(key, formatter)
  }
  return formatter
}

function dateFormat(locale: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  return cached(`d:${locale}:${JSON.stringify(options)}`, () => new Intl.DateTimeFormat(locale, options))
}

/** Parse an RFC 3339 string, or `null` if it is absent or malformed. */
export function parseInstant(value: string | null | undefined): Date | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/** Absolute date and time in the active locale. */
export function formatInstant(value: string | null | undefined, locale: string): string | null {
  const date = parseInstant(value)
  if (!date) return null
  return dateFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

/**
 * "3 hours ago" in the active locale, via `Intl.RelativeTimeFormat` so the
 * Turkish rendering is grammatical rather than an English string with a
 * translated noun glued on.
 */
export function formatRelative(
  value: string | null | undefined,
  locale: string,
  now: Date = new Date(),
): string | null {
  const date = parseInstant(value)
  if (!date) return null

  const rtf = cached(`r:${locale}`, () => new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }))
  const delta = date.getTime() - now.getTime()
  const abs = Math.abs(delta)

  if (abs < MINUTE) return rtf.format(Math.round(delta / 1000), 'second')
  if (abs < HOUR) return rtf.format(Math.round(delta / MINUTE), 'minute')
  if (abs < DAY) return rtf.format(Math.round(delta / HOUR), 'hour')
  return rtf.format(Math.round(delta / DAY), 'day')
}

/** Whether an instant is still in the future — a lockout that has not lapsed. */
export function isFuture(value: string | null | undefined, now: Date = new Date()): boolean {
  const date = parseInstant(value)
  return date !== null && date.getTime() > now.getTime()
}

/**
 * A file-list date, the way Drive and Dolphin show it: the time for today,
 * day and month for this year, the full date otherwise. The absolute instant
 * belongs in a tooltip or the details panel (`formatInstant`).
 */
export function formatFileDate(
  value: string | null | undefined,
  locale: string,
  now: Date = new Date(),
): string | null {
  const date = parseInstant(value)
  if (!date) return null
  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate()
  if (sameDay) return dateFormat(locale, { timeStyle: 'short' }).format(date)
  if (date.getFullYear() === now.getFullYear()) {
    return dateFormat(locale, { day: 'numeric', month: 'short' }).format(date)
  }
  return dateFormat(locale, { dateStyle: 'medium' }).format(date)
}

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const

/**
 * Binary sizes (1 KB = 1024 B, matching what quotas are enforced in) with the
 * decimal separator from the active locale. The unit symbols are the same in
 * every language Kutup ships, and Intl's own byte units spell the smallest
 * one out ("0 byte"), so symbols are appended here.
 */
export function formatBytes(bytes: number, locale: string): string {
  let value = Math.max(0, bytes)
  let unit = 0
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  const digits = unit === 0 ? 0 : unit < 3 ? 1 : 2
  const number = cached(`n:${locale}:${digits}`, () => new Intl.NumberFormat(locale, { maximumFractionDigits: digits })).format(value)
  return `${number} ${BYTE_UNITS[unit]}`
}

/** Transfer speed, e.g. "4.2 MB/s"; empty when there is no rate yet. */
export function formatSpeed(bytesPerSecond: number, locale: string): string {
  if (bytesPerSecond <= 0) return ''
  return `${formatBytes(bytesPerSecond, locale)}/s`
}
