/**
 * Tiny date formatters used by the mobile pages — ported from the Claude
 * Design handoff prototype.
 *
 * Locale-aware (uses the browser's locale via `Intl.DateTimeFormat` defaults).
 * If the input is null/undefined/invalid, returns an em-dash.
 */

export function formatDateShort(s: string | null | undefined): string {
  if (!s) return '—'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function formatDateLong(s: string | null | undefined): string {
  if (!s) return '—'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

/** "3 minutes ago" / "2 days ago" — falls back to the short date beyond a week. */
export function formatTimeAgo(s: string | null | undefined): string {
  if (!s) return '—'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return '—'
  const seconds = Math.round((d.getTime() - Date.now()) / 1000)
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  const abs = Math.abs(seconds)
  if (abs < 60) return rtf.format(Math.trunc(seconds), 'second')
  if (abs < 3600) return rtf.format(Math.trunc(seconds / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.trunc(seconds / 3600), 'hour')
  if (abs < 7 * 86400) return rtf.format(Math.trunc(seconds / 86400), 'day')
  return formatDateShort(s)
}
