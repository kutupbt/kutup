import { describe, expect, it } from 'vitest'
import { formatBytes, formatFileDate } from './format'

describe('formatBytes', () => {
  it('uses binary units with symbols, in the locale\'s number format', () => {
    expect(formatBytes(0, 'en')).toBe('0 B')
    expect(formatBytes(1536, 'en')).toBe('1.5 KB')
    expect(formatBytes(10 * 1024 ** 3, 'en')).toBe('10 GB')
    expect(formatBytes(1536, 'tr')).toBe('1,5 KB')
  })
})

describe('formatFileDate', () => {
  const now = new Date('2026-09-23T15:00:00')
  it('shows the time today, day and month this year, the full date before', () => {
    expect(formatFileDate('2026-09-23T09:05:00', 'en-GB', now)).toBe('09:05')
    expect(formatFileDate('2026-03-02T09:05:00', 'en-GB', now)).toBe('2 Mar')
    expect(formatFileDate('2024-03-02T09:05:00', 'en-GB', now)).toBe('2 Mar 2024')
  })
  it('returns null for missing or malformed input', () => {
    expect(formatFileDate(null, 'en', now)).toBeNull()
    expect(formatFileDate('not a date', 'en', now)).toBeNull()
  })
})
