import { describe, it, expect } from 'vitest'
import { usersToCsv } from './csv'
import type { UserRow } from '@/types/api'

function makeUser(overrides: Partial<UserRow> = {}): UserRow {
  return {
    id: 'u1',
    email: 'maya@kutup.cloud',
    username: 'maya.k',
    storageQuotaBytes: 10_737_418_240,
    storageUsedBytes: 4_509_715_200,
    isAdmin: false,
    isActive: true,
    totpEnabled: true,
    createdAt: '2026-04-22T09:00:00Z',
    isProtected: false,
    ...overrides,
  }
}

describe('usersToCsv', () => {
  it('emits a header even for an empty list', () => {
    const csv = usersToCsv([])
    expect(csv).toMatch(/^email,username,isAdmin,isActive,totpEnabled,storageUsedBytes,storageQuotaBytes,createdAt\n$/)
  })

  it('renders one row per user with stable column order', () => {
    const csv = usersToCsv([makeUser()])
    const lines = csv.trim().split('\n')
    expect(lines).toHaveLength(2)
    expect(lines[1]).toBe(
      'maya@kutup.cloud,maya.k,false,true,true,4509715200,10737418240,2026-04-22T09:00:00Z',
    )
  })

  it('RFC-4180 quotes fields with comma / quote / newline', () => {
    // Asserted against the full string — splitting by `\n` would break the
    // quoted newline case (the field itself contains a literal newline).
    const csvComma = usersToCsv([makeUser({ username: 'has,comma' })])
    expect(csvComma).toContain('"has,comma"')

    const csvQuote = usersToCsv([makeUser({ email: 'has"quote@kutup.cloud' })])
    expect(csvQuote).toContain('"has""quote@kutup.cloud"')

    const csvNewline = usersToCsv([makeUser({ username: 'has\nnewline' })])
    expect(csvNewline).toContain('"has\nnewline"')
  })

  it('ends with a trailing newline', () => {
    expect(usersToCsv([makeUser()])).toMatch(/\n$/)
  })
})
