import type { MeetingInfo } from './callLinks'

// A scheduled meeting as an iCalendar file (RFC 5545), so it can go into
// whatever calendar a person uses. Kutup keeps no calendar of its own.

/** Escape a TEXT value: backslash, semicolon, comma and line breaks. */
function text(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n')
}

/** `YYYYMMDDTHHMMSSZ` in UTC. */
function utc(ms: number): string {
  return new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')
}

/** Lines are at most 75 octets; a longer one continues after CRLF + space. */
function fold(line: string): string {
  const encoder = new TextEncoder()
  const parts: string[] = []
  let current = ''
  let size = 0
  for (const char of line) {
    const bytes = encoder.encode(char).length
    // Continuation lines begin with a space, which counts.
    if (size + bytes > (parts.length === 0 ? 75 : 74)) {
      parts.push(current)
      current = ''
      size = 0
    }
    current += char
    size += bytes
  }
  parts.push(current)
  return parts.join('\r\n ')
}

/**
 * The calendar file of a scheduled meeting; null when it has no start time.
 * Without a set length it is entered as one hour.
 */
export function meetingIcs(meeting: { roomId: string; url: string; info: MeetingInfo }, nowMs: number): string | null {
  const { info } = meeting
  if (info.startsAtMs === undefined) return null
  const end = info.startsAtMs + (info.durationMinutes ?? 60) * 60_000
  const host = new URL(meeting.url).hostname
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Kutup//Chat meetings//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    `UID:${meeting.roomId}@${host}`,
    `DTSTAMP:${utc(nowMs)}`,
    `DTSTART:${utc(info.startsAtMs)}`,
    `DTEND:${utc(end)}`,
    `SUMMARY:${text(info.title)}`,
    `DESCRIPTION:${text(meeting.url)}`,
    `LOCATION:${text(meeting.url)}`,
    `URL:${meeting.url}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ]
  return lines.map(fold).join('\r\n') + '\r\n'
}

/** A file name from the title: letters and digits, dashes between. */
export function icsFileName(title: string): string {
  const base = title
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
  return `${base || 'meeting'}.ics`
}

/** Hand the meeting's calendar file to the browser to save. */
export function downloadMeetingIcs(meeting: { roomId: string; url: string; info: MeetingInfo }): boolean {
  const ics = meetingIcs(meeting, Date.now())
  if (!ics) return false
  const href = URL.createObjectURL(new Blob([ics], { type: 'text/calendar;charset=utf-8' }))
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = icsFileName(meeting.info.title)
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(href)
  return true
}
