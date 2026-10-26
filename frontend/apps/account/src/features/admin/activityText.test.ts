import { describe, expect, it } from 'vitest'
import type { AdminActivityEntry } from '@kutup/session/api-types'
import { i18n } from '@kutup/i18n'
import '../../testI18n'
import { activitySentence } from './activityText'

const t = i18n.t.bind(i18n)

function entry(action: string, payload: Record<string, unknown>): AdminActivityEntry {
  return {
    id: 1,
    action,
    adminUserId: 'a1',
    adminUsername: 'admin',
    targetUserId: 'u1',
    targetUsername: 'bob',
    payload,
    occurredAt: '2026-10-26T00:00:00Z',
  }
}

describe("An account's limits in the activity log", () => {
  it('names a rate limit by its name on the page', () => {
    expect(activitySentence(entry('user.rate_limit', { key: 'feedback', value: 5 }), t)).toBe(
      'admin set Feedback sent to 5 for bob',
    )
    expect(activitySentence(entry('user.rate_limit', { key: 'feedback', value: null }), t)).toBe(
      "admin gave bob the server's Feedback sent again",
    )
  })

  it('names a setting by its section and field', () => {
    const upload = { key: 'drive_upload_max_bytes', field: 'driveUploadMaxBytes', section: 'drive' }
    expect(activitySentence(entry('user.setting', { ...upload, value: 1048576 }), t)).toBe(
      'admin set Largest upload (bytes) to 1048576 for bob',
    )
    expect(activitySentence(entry('user.setting', { ...upload, value: null }), t)).toBe(
      "admin gave bob the server's Largest upload (bytes) again",
    )
  })
})
