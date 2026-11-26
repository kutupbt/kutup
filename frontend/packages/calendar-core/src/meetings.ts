import { createOwnedCallLink, callLinkFragmentOf, updateOwnedCallLinkInfo, type MeetingInfo, type OwnedCallLink, type OwnerCallLinkCrypto } from '@kutup/chat-core/ownedMeetings'
import { calendarCallLinkRuntime } from '@kutup/crypto/calendar'
import { appUrl, loadServerSettings } from '@kutup/session/apps'
import type { Session } from '@kutup/session/store'

// Kutup meetings in events (docs/plans/calendar.md, E5c): a Chat meeting
// made from the event editor, its link kept in the event's encrypted part
// (RFC 7986 CONFERENCE). The calendar runtime makes the link; Chat opens it.

/** The longest meeting title, in UTF-8 bytes (`MAX_CALL_TITLE_BYTES`). */
const MAX_TITLE_BYTES = 200
/** The longest planned meeting (`MAX_CALL_DURATION_MINUTES`). */
const MAX_MINUTES = 24 * 60

async function runtime(): Promise<OwnerCallLinkCrypto> {
  return (await calendarCallLinkRuntime()) as OwnerCallLinkCrypto
}

/** Whether this server hosts meetings (`chat.callLinks`: it has a call server). */
export async function meetingsAvailable(): Promise<boolean> {
  const settings = await loadServerSettings<{ chat?: { callLinks?: boolean } }>()
  return settings.chat?.callLinks === true
}

/** Where Chat opens meetings: its app's origin. */
export function chatOrigin(): string {
  return new URL(appUrl('chat')).origin
}

/** A title the meeting takes: trimmed, cut to whole characters within the byte limit. */
function meetingTitle(title: string, fallback: string): string {
  const encoder = new TextEncoder()
  let text = title.replace(/\p{Cc}/gu, ' ').trim() || fallback
  while (encoder.encode(text).length > MAX_TITLE_BYTES) text = [...text].slice(0, -1).join('').trimEnd()
  return text
}

/**
 * A meeting's title and time from an event's: its start, and its length when
 * it has one within a day. An all-day event's meeting has no time.
 */
export function meetingInfoOf(event: { title: string; startUtc: string; endUtc: string; fullDay: boolean }, fallbackTitle: string): MeetingInfo {
  const title = meetingTitle(event.title, fallbackTitle)
  if (event.fullDay) return { title }
  const startsAtMs = Date.parse(event.startUtc)
  const minutes = Math.round((Date.parse(event.endUtc) - startsAtMs) / 60_000)
  if (!(startsAtMs > 0)) return { title }
  return minutes >= 1 && minutes <= MAX_MINUTES ? { title, startsAtMs, durationMinutes: minutes } : { title, startsAtMs }
}

/** Makes a Kutup meeting for an event: the account's own, listed in Chat with its others. */
export async function makeMeeting(session: Session, info: MeetingInfo): Promise<OwnedCallLink> {
  return createOwnedCallLink(await runtime(), session.roots.callLinkRoot, info, chatOrigin())
}

/** Whether `url` is a Kutup meeting link of this server's Chat. */
export function isKutupMeeting(url: string): boolean {
  try {
    return new URL(url).origin === chatOrigin() && new URL(url).pathname === '/call' && callLinkFragmentOf(url) !== null
  } catch {
    return false
  }
}

/**
 * Gives a meeting the event's new title and time. Only the meeting's owner
 * can: anyone else's link (an invitation's) is left as it is, and so is one
 * the server no longer has.
 */
export async function followEvent(url: string, info: MeetingInfo): Promise<boolean> {
  if (!isKutupMeeting(url)) return false
  const crypto = await runtime()
  const fragment = callLinkFragmentOf(url)!
  const roomId = crypto.callLinkKeys(crypto.callLinkParse(fragment)).roomId
  try {
    await updateOwnedCallLinkInfo(crypto, { roomId, url }, info)
    return true
  } catch {
    return false
  }
}
