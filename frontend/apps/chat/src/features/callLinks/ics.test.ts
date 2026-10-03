import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/chat-core/wasm', () => ({ loadChatWasm: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: {} }))
vi.mock('@kutup/crypto', () => ({ toBase64: vi.fn() }))

const { icsFileName, meetingIcs } = await import('./ics')

const url = 'https://chat.example.org/call#' + 'A'.repeat(44)
const start = Date.UTC(2026, 9, 6, 14, 0)
const now = Date.UTC(2026, 9, 3, 9, 30, 15)

describe('meetingIcs', () => {
  it('writes one event in UTC with the link', () => {
    const ics = meetingIcs({ roomId: 'ab'.repeat(16), url, info: { title: 'Team sync', startsAtMs: start, durationMinutes: 45 } }, now)!
    expect(ics.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\n')).toBe(true)
    expect(ics.endsWith('END:VEVENT\r\nEND:VCALENDAR\r\n')).toBe(true)
    expect(ics).toContain(`UID:${'ab'.repeat(16)}@chat.example.org\r\n`)
    expect(ics).toContain('DTSTAMP:20261003T093015Z\r\n')
    expect(ics).toContain('DTSTART:20261006T140000Z\r\n')
    expect(ics).toContain('DTEND:20261006T144500Z\r\n')
    expect(ics).toContain('SUMMARY:Team sync\r\n')
    // Long lines fold; unfolded, the link is whole.
    expect(ics.replace(/\r\n /g, '')).toContain(`URL:${url}\r\n`)
    expect(ics.split('\r\n').every((line) => new TextEncoder().encode(line).length <= 75)).toBe(true)
  })

  it('enters a meeting without a set length as one hour', () => {
    const ics = meetingIcs({ roomId: 'ab'.repeat(16), url, info: { title: 'Open end', startsAtMs: start } }, now)!
    expect(ics).toContain('DTEND:20261006T150000Z\r\n')
  })

  it('escapes what a title may contain', () => {
    const ics = meetingIcs({ roomId: 'ab'.repeat(16), url, info: { title: 'Plan; budget, Q4 \\ review', startsAtMs: start } }, now)!
    expect(ics).toContain('SUMMARY:Plan\\; budget\\, Q4 \\\\ review\r\n')
  })

  it('has nothing to offer for a meeting without a time', () => {
    expect(meetingIcs({ roomId: 'ab'.repeat(16), url, info: { title: 'Any time' } }, now)).toBeNull()
  })
})

describe('icsFileName', () => {
  it('makes a safe name from the title', () => {
    expect(icsFileName('Team sync / Q4: plan')).toBe('Team-sync-Q4-plan.ics')
    expect(icsFileName('Toplantı günü')).toMatch(/^Toplant.*g.*n.*\.ics$/)
    expect(icsFileName('***')).toBe('meeting.ics')
  })
})
