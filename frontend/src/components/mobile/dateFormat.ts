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
