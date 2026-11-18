import { describe, expect, it } from 'vitest'
import type { AdminActivityEntry } from '@kutup/session/api-types'
import { i18n } from '@kutup/i18n'
import '../../testI18n'
import { activitySentence } from './activityText'

const t = i18n.t.bind(i18n)

function entry(action: string, payload: Record<string, unknown>, targetUsername: string | null = 'bob'): AdminActivityEntry {
  return {
    id: 1,
    action,
    adminAccountId: 'a1',
    adminUsername: 'admin',
    targetAccountId: 'u1',
    targetUsername,
    payload,
    occurredAt: '2026-10-26T00:00:00Z',
  }
}

describe("An account's limits in the activity log", () => {
  it('names a rate limit by its name on the page', () => {
    expect(activitySentence(entry('account.setRateLimit', { key: 'feedback', value: 5 }), t)).toBe(
      'admin set Feedback sent to 5 for bob',
    )
    expect(activitySentence(entry('account.setRateLimit', { key: 'feedback', value: null }), t)).toBe(
      "admin gave bob the server's Feedback sent again",
    )
  })

  it('names a setting by its section and field', () => {
    const upload = { key: 'drive_upload_max_bytes', field: 'driveUploadMaxBytes', section: 'drive' }
    expect(activitySentence(entry('account.setEntitlement', { ...upload, value: 1048576 }), t)).toBe(
      'admin set Largest upload (bytes) to 1048576 for bob',
    )
    expect(activitySentence(entry('account.setEntitlement', { ...upload, value: null }), t)).toBe(
      "admin gave bob the server's Largest upload (bytes) again",
    )
  })
})

describe('Accounts in the activity log', () => {
  it('names a deleted account as such', () => {
    expect(activitySentence(entry('account.delete', {}, null), t)).toBe('admin deleted a deleted account')
    expect(activitySentence(entry('account.create', { storageQuotaBytes: 1 }), t)).toBe('admin created bob')
  })

  it('shows an action without a sentence by its id', () => {
    expect(activitySentence(entry('mailDomain.approve', { domain: 'example.org' }), t)).toBe('admin: mailDomain.approve')
  })
})
