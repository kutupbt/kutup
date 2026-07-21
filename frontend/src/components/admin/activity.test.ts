import { describe, expect, it } from 'vitest'
import type { TFunction } from 'i18next'
import type { AdminActivityEntry } from '@/types/api'
import { activityAdmin, activityDetails, activityText } from './activity'

const t = ((_key: string, fallback: string, values?: Record<string, unknown>) =>
  Object.entries(values ?? {}).reduce(
    (text, [key, value]) => text.replaceAll(`{{${key}}}`, String(value)),
    fallback,
  )) as TFunction

function event(action: string, payload: Record<string, unknown>): AdminActivityEntry {
  return {
    id: 1,
    action,
    adminUserId: '00000000-0000-0000-0000-000000000000',
    adminEmail: null,
    adminUsername: null,
    targetUserId: null,
    targetEmail: null,
    payload,
    occurredAt: '2026-07-21T10:00:00Z',
  }
}

describe('federation audit presentation', () => {
  it('distinguishes system identity events from deleted administrators', () => {
    const entry = event('federation.identity.pin', { domain: 'chat.example.com' })
    expect(activityAdmin(entry, t)).toBe('system/operator')
    expect(activityText(entry, t)).toBe('system/operator pinned chat.example.com by TOFU')
  })

  it('keeps old/new fingerprints and quarantine reasons visible', () => {
    const entry = event('federation.identity.quarantine', {
      domain: 'chat.example.com',
      reason: 'same-sequence identity conflict',
      retainedFingerprint: 'a'.repeat(64),
      candidateFingerprint: 'b'.repeat(64),
    })
    expect(activityDetails(entry)).toEqual([
      'domain: chat.example.com',
      `retained fingerprint: ${'a'.repeat(64)}`,
      `candidate fingerprint: ${'b'.repeat(64)}`,
      'reason: same-sequence identity conflict',
    ])
  })

  it('labels the selected feature instead of hard-coding Chat', () => {
    const entry = event('federation.policy.update', { feature: 'drive', mode: 'open' })
    expect(activityText(entry, t)).toBe('system/operator changed drive federation mode to open')
  })
})
