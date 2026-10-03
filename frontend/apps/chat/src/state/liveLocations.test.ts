import { describe, expect, it } from 'vitest'
import type { ChatHistoryEntry, ChatLiveLocationV1 } from '@kutup/chat-core/types'
import { foldLiveLocations, liveShareEnded } from './liveLocations'

const SHARE = '0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b'
const conversation = { kind: 'group' as const, groupId: 'g1' }

function live(generation: number, streamId: string, untilMs = 10_000): ChatLiveLocationV1 {
  return { shareId: SHARE, generation, server: 'a.test', streamId, key: 'k', readCapability: 'r', untilMs }
}

function entry(id: string, peer: string, content: Record<string, unknown>, timestampMs = 1): ChatHistoryEntry {
  return {
    id,
    conversation,
    peer,
    direction: 'incoming',
    timestampMs,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'x', sentAt: '', seq: '1', messageId: id, ...content },
  } as unknown as ChatHistoryEntry
}

const actor = (m: ChatHistoryEntry) => m.peer

describe('foldLiveLocations', () => {
  it('follows the sharer’s newer streams and stop, not anyone else’s', () => {
    const shares = foldLiveLocations(
      [
        entry('m1', 'alice@a.test', { liveLocation: live(1, 'aa') }),
        entry('m2', 'alice@a.test', { liveLocation: live(2, 'bb', 99_999) }),
        entry('m3', 'mallory@a.test', { liveLocation: live(3, 'cc') }),
        entry('m4', 'mallory@a.test', { liveLocationStop: { shareId: SHARE } }, 5),
      ],
      actor,
    )
    const state = shares.get('m1')!
    expect(state.latest.streamId).toBe('bb')
    expect(state.latest.untilMs).toBe(10_000) // never extended
    expect(state.stoppedAtMs).toBeNull()
    expect(shares.has('m3')).toBe(false)
  })

  it('ends at the stop or the end time', () => {
    const shares = foldLiveLocations(
      [entry('m1', 'alice@a.test', { liveLocation: live(1, 'aa') }), entry('m2', 'alice@a.test', { liveLocationStop: { shareId: SHARE } }, 7)],
      actor,
    )
    expect(shares.get('m1')!.stoppedAtMs).toBe(7)
    expect(liveShareEnded(shares.get('m1')!, 1)).toBe(true)
    const running = foldLiveLocations([entry('m1', 'alice@a.test', { liveLocation: live(1, 'aa') })], actor).get('m1')!
    expect(liveShareEnded(running, 9_999)).toBe(false)
    expect(liveShareEnded(running, 10_000)).toBe(true)
  })
})
