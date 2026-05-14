import type { UserRow } from '@/types/api'

/**
 * CSV helpers for the admin Users tab. Pure functions (no DOM in `usersToCsv`)
 * so they're easy to unit-test; `downloadCsv` triggers the browser download.
 *
 * The format mirrors what an admin would expect for an audit / handoff:
 * one row per user, header included, RFC-4180 quoting on any field with a
 * comma / quote / newline.
 */

const HEADERS = [
  'email',
  'username',
  'isAdmin',
  'isActive',
  'totpEnabled',
  'storageUsedBytes',
  'storageQuotaBytes',
  'createdAt',
] as const

/** Quote a field per RFC-4180 if it contains comma, quote, or newline. */
function csvField(v: string | number | boolean): string {
  const s = String(v)
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

/**
 * Render a CSV string from a `UserRow[]`. Header is always included even
 * for an empty list — keeps the file shape predictable for downstream tooling.
 */
export function usersToCsv(users: UserRow[]): string {
  const lines: string[] = [HEADERS.join(',')]
  for (const u of users) {
    lines.push(
      [
        u.email,
        u.username,
        u.isAdmin,
        u.isActive,
        u.totpEnabled,
        u.storageUsedBytes,
        u.storageQuotaBytes,
        u.createdAt,
      ]
        .map(csvField)
        .join(','),
    )
  }
  // Trailing newline — most tools expect one
  return lines.join('\n') + '\n'
}

/**
 * Trigger a browser download of the given CSV content.
 * Browser-only; do NOT call from a vitest test without mocking.
 */
export function downloadCsv(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  // Defer revocation so the navigation/save dialog has time to read the URL
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
