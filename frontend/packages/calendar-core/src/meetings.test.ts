import { beforeEach, describe, expect, it, vi } from 'vitest'

const server = vi.hoisted(() => ({ posts: [] as [string, unknown][], puts: [] as [string, unknown][], failPut: false }))
vi.mock('@kutup/session/client', () => ({
  default: {
    post: (url: string, body: { roomId: string; nonce: string; info: string; waitingRoom: boolean }) => {
      server.posts.push([url, body])
      return Promise.resolve({ data: { roomId: body.roomId, nonce: body.nonce, info: body.info, waitingRoom: body.waitingRoom, createdAt: '2026-11-26T00:00:00Z' } })
    },
    put: (url: string, body: unknown) => {
      server.puts.push([url, body])
      return server.failPut ? Promise.reject(new Error('403')) : Promise.resolve({ data: {} })
    },
  },
}))
vi.mock('@kutup/session/apps', () => ({ appUrl: () => 'https://chat.kutup.test/', loadServerSettings: () => Promise.resolve({ chat: { callLinks: true } }) }))
// The calendar runtime's meeting-link functions, as a deterministic fake.
const fragment = 'A'.repeat(44)
vi.mock('@kutup/crypto/calendar', () => ({
  calendarCallLinkRuntime: () =>
    Promise.resolve({
      callLinkNonce: () => 'n'.repeat(32),
      callLinkOwnerSecret: (_root: string, nonce: string) => `secret:${nonce}`,
      callLinkHostToken: () => ({ hostToken: 'host', hostTokenHash: 'host-hash' }),
      callLinkKeys: () => ({ roomId: 'r'.repeat(32), accessToken: 'a', accessTokenHash: 'a-hash', frameKey: 'f' }),
      callLinkFragment: () => fragment,
      callLinkParse: () => 'secret:parsed',
      callLinkSealInfo: (_secret: string, info: unknown) => JSON.stringify(info),
      callLinkOpenInfo: (_secret: string, sealed: string) => JSON.parse(sealed),
    }),
}))

import { followEvent, isKutupMeeting, makeMeeting, meetingInfoOf } from './meetings'

beforeEach(() => {
  server.posts = []
  server.puts = []
  server.failPut = false
})

describe('a meeting from an event', () => {
  const event = { title: 'Planning', startUtc: '2026-12-01T09:00:00Z', endUtc: '2026-12-01T10:30:00Z', fullDay: false }

  it('takes the event title, start and length', () => {
    expect(meetingInfoOf(event, 'Meeting')).toEqual({ title: 'Planning', startsAtMs: Date.parse(event.startUtc), durationMinutes: 90 })
  })

  it('has no time for an all-day event, a fallback title, and no length past a day', () => {
    expect(meetingInfoOf({ ...event, fullDay: true }, 'Meeting')).toEqual({ title: 'Planning' })
    expect(meetingInfoOf({ ...event, title: '  \u0007 ' }, 'Meeting').title).toBe('Meeting')
    expect(meetingInfoOf({ ...event, endUtc: '2026-12-03T09:00:00Z' }, 'Meeting')).toEqual({ title: 'Planning', startsAtMs: Date.parse(event.startUtc) })
  })

  it('cuts a long title to 200 bytes of whole characters', () => {
    const title = meetingInfoOf({ ...event, title: 'ş'.repeat(150) }, 'Meeting').title
    expect(new TextEncoder().encode(title).length).toBeLessThanOrEqual(200)
    expect(title).toBe('ş'.repeat(100))
  })
})

describe("Kutup meetings in events", () => {
  it('makes the meeting at this server and links it at Chat', async () => {
    const meeting = await makeMeeting({ roots: { callLinkRoot: 'root' } } as never, { title: 'Planning' })
    expect(meeting.url).toBe(`https://chat.kutup.test/call#${fragment}`)
    expect(server.posts[0][0]).toBe('/chat/call-links')
    expect(isKutupMeeting(meeting.url)).toBe(true)
  })

  it('knows only its own Chat links as Kutup meetings', () => {
    expect(isKutupMeeting(`https://chat.kutup.test/call#${fragment}`)).toBe(true)
    expect(isKutupMeeting(`https://evil.example/call#${fragment}`)).toBe(false)
    expect(isKutupMeeting('https://chat.kutup.test/call#short')).toBe(false)
    expect(isKutupMeeting('not a url')).toBe(false)
  })

  it('follows the event, and leaves a link it may not change alone', async () => {
    const url = `https://chat.kutup.test/call#${fragment}`
    expect(await followEvent(url, { title: 'Moved' })).toBe(true)
    expect(server.puts[0][0]).toBe(`/chat/call-links/${'r'.repeat(32)}/info`)
    server.failPut = true
    expect(await followEvent(url, { title: 'Moved' })).toBe(false)
    expect(await followEvent('https://meet.example/x', { title: 'Moved' })).toBe(false)
    expect(server.puts).toHaveLength(2)
  })
})
