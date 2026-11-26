import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/session/apps', () => ({ appUrl: (app: string) => `https://${app}.kutup.test/` }))
// UTC as the zone: the local time is the instant's own.
vi.mock('@kutup/crypto/calendar', () => ({ utcToLocal: (instant: string) => Promise.resolve(instant.slice(0, 19)) }))

import { calendarMeetingUrl } from '@kutup/chat-core/ownedMeetings'
import { meetingTarget } from './meetingLink'

const link = `https://chat.kutup.test/call#${'A'.repeat(44)}`

function fragmentOf(url: string): string {
  return url.slice(url.indexOf('#'))
}

describe("Chat's Add to Kutup Calendar", () => {
  it('opens a new event at the meeting time, with its link and title', async () => {
    const url = calendarMeetingUrl('https://calendar.kutup.test/', {
      url: link,
      info: { title: 'Planning', startsAtMs: Date.parse('2026-12-01T23:30:00Z'), durationMinutes: 60 },
    })
    expect(url.startsWith('https://calendar.kutup.test/#')).toBe(true)
    expect(await meetingTarget(fragmentOf(url), 'UTC', '2026-11-26')).toEqual({
      kind: 'new',
      date: '2026-12-01',
      minutes: 23 * 60 + 30,
      endMinutes: 30,
      endDate: '2026-12-02',
      title: 'Planning',
      conference: link,
    })
  })

  it('opens today without a time when the meeting has none', async () => {
    const url = calendarMeetingUrl('https://calendar.kutup.test/', { url: link, info: { title: 'Any time' } })
    expect(await meetingTarget(fragmentOf(url), 'UTC', '2026-11-26')).toEqual({ kind: 'new', date: '2026-11-26', title: 'Any time', conference: link })
  })

  it("takes no link but this server's Chat meetings", async () => {
    for (const other of ['https://evil.example/call#' + 'A'.repeat(44), 'javascript:alert(1)', 'https://chat.kutup.test/call#short']) {
      const url = calendarMeetingUrl('https://calendar.kutup.test/', { url: other, info: { title: 'X' } })
      expect(await meetingTarget(fragmentOf(url), 'UTC', '2026-11-26')).toBeNull()
    }
  })
})
