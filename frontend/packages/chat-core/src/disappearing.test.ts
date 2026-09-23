import { describe, expect, it } from 'vitest'
import {
  disappearingMessageExpiresAt,
  formatRemainingTime,
  isVisibleChatMessage,
  reduceDisappearingTimers,
} from './disappearing'
import type { ChatHistoryEntry } from './types'

function entry(
  id: string,
  timestampMs: number,
  content: ChatHistoryEntry['content'],
): ChatHistoryEntry {
  return {
    id,
    conversation: { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
    peer: 'bob@b.test',
    direction: 'incoming',
    senderDeviceId: 1,
    timestampMs,
    delivered: true,
    deduplicated: false,
    content,
  }
}

describe('disappearing Chat presentation', () => {
  it('reduces encrypted timer controls deterministically and preserves off', () => {
    const enabled = entry('timer-enabled', 1_000, {
      version: 1,
      kind: 'disappearingTimer',
      sentAt: '2026-08-10T00:00:00Z',
      seq: '8',
      body: { durationSeconds: 3_600 },
      disappearingTimer: { durationSeconds: 3_600 },
    })
    const disabled = entry('timer-disabled', 1_000, {
      version: 1,
      kind: 'disappearingTimer',
      sentAt: '2026-08-10T00:00:01Z',
      seq: '9',
      body: {},
      disappearingTimer: {},
    })

    const timer = reduceDisappearingTimers([disabled, enabled]).get('direct:bob@b.test')
    expect(timer?.message.id).toBe('timer-disabled')
    expect(timer?.durationSeconds).toBeUndefined()
  })

  it('uses the core-computed absolute expiry instead of restarting locally', () => {
    const message = entry('temporary', 10_000, {
      version: 1,
      kind: 'text',
      sentAt: '2026-08-10T00:00:00Z',
      seq: '1',
      body: { text: 'temporary' },
      text: 'temporary',
      expiresAfterSeconds: 30,
      expiresAtMs: 40_000,
    })

    expect(disappearingMessageExpiresAt(message)).toBe(40_000)
    expect(isVisibleChatMessage(message, 39_999)).toBe(true)
    expect(isVisibleChatMessage(message, 40_000)).toBe(false)
  })

  it('keeps an unread incoming disappearing message until first view', () => {
    const message = entry('unread-temporary', 10_000, {
      version: 1,
      kind: 'text',
      sentAt: '2026-08-10T00:00:00Z',
      seq: '1',
      body: { text: 'unread temporary' },
      text: 'unread temporary',
      expiresAfterSeconds: 30,
    })

    expect(disappearingMessageExpiresAt(message)).toBeUndefined()
    expect(isVisibleChatMessage(message, 1_000_000)).toBe(true)
  })

  it('hides timer and derived controls and formats a bounded countdown', () => {
    const timer = entry('timer', 1, {
      version: 1,
      kind: 'disappearingTimer',
      sentAt: 't',
      seq: '1',
      body: {},
      disappearingTimer: {},
    })
    expect(isVisibleChatMessage(timer, 1)).toBe(false)
    expect(formatRemainingTime(30_001)).toBe('31s')
    expect(formatRemainingTime(3_600_000)).toBe('1h')
    expect(formatRemainingTime(-1)).toBe('0s')
  })
})
