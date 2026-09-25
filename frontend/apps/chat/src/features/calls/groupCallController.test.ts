import { describe, expect, it, vi } from 'vitest'

vi.mock('livekit-client', () => ({
  BaseKeyProvider: class {},
  createKeyMaterialFromBuffer: vi.fn(),
  Room: class {},
  RoomEvent: {},
  Track: { Source: {} },
}))

const { activeGroupCall } = await import('./groupCallController')

const call = (callId: string, event: 'started' | 'ended') => ({
  callId,
  event,
  host: 'a.test',
  roomId: '0'.repeat(32),
  media: 'audio' as const,
  secret: 'AAAA',
})

describe('activeGroupCall', () => {
  const now = Date.UTC(2026, 8, 25, 12)
  it('is the latest call started and not ended', () => {
    expect(activeGroupCall([
      { call: call('a', 'started'), atMs: now - 60_000 },
      { call: call('b', 'started'), atMs: now - 30_000 },
      { call: call('b', 'ended'), atMs: now - 10_000 },
    ], now)?.callId).toBe('a')
  })

  it('forgets a call nobody ended after half a day', () => {
    expect(activeGroupCall([{ call: call('a', 'started'), atMs: now - 13 * 60 * 60 * 1000 }], now)).toBeNull()
  })
})
