import type { CallLinkRoot } from '@kutup/crypto/accountRoots'
import api from '@kutup/session/client'
import type { CallLinkCrypto, CallLinkInfo } from './types'

// A meeting an account owns (docs/chat-calls.md, "Meetings"): made, listed
// and renamed from the owner's call-link root. Shared by Chat and Calendar
// (docs/plans/calendar.md, E5c), each passing its own runtime: Chat's engine,
// or the `crypto-calendar` runtime, which exports these functions under the
// same names. Nothing here loads a runtime itself.

/** What making and changing an own meeting needs of a runtime. */
export type OwnerCallLinkCrypto = Pick<
  CallLinkCrypto,
  | 'callLinkNonce'
  | 'callLinkOwnerSecret'
  | 'callLinkHostToken'
  | 'callLinkKeys'
  | 'callLinkFragment'
  | 'callLinkParse'
  | 'callLinkSealInfo'
  | 'callLinkOpenInfo'
>

export type MeetingInfo = CallLinkInfo

/** One of the account's own meetings. */
export interface OwnedCallLink {
  roomId: string
  createdAt: string
  url: string
  info: MeetingInfo
  /** People who open the link wait until the owner lets them in. */
  waitingRoom: boolean
  /** Public; the owner's devices derive the meeting's secrets from it. */
  nonce: string
  /** The owner's proof of being the host (standard base64). */
  hostToken: string
}

/** A meeting as the server stores it. */
export interface StoredCallLink {
  roomId: string
  nonce: string
  info: string
  waitingRoom: boolean
  createdAt: string
}

/** Where a meeting opens: the Chat app at `chatOrigin`, the secret in the fragment. */
export function meetingUrl(chatOrigin: string, fragment: string): string {
  return `${chatOrigin.replace(/\/+$/, '')}/call#${fragment}`
}

/**
 * The fragment of something a person pasted or opened: a whole link, or the
 * fragment alone. Null when it does not look like one.
 */
export function callLinkFragmentOf(value: string): string | null {
  const text = value.trim()
  const hash = text.indexOf('#')
  const fragment = hash >= 0 ? text.slice(hash + 1) : text
  // base64url of version (1) + secret (32): 44 characters.
  return /^[A-Za-z0-9_-]{44}$/.test(fragment) ? fragment : null
}

/** A stored meeting as its owner sees it; null when this account's key doesn't explain it. */
export function ownedCallLink(crypto: OwnerCallLinkCrypto, callLinkRoot: CallLinkRoot, stored: StoredCallLink, chatOrigin: string): OwnedCallLink | null {
  const secret = crypto.callLinkOwnerSecret(callLinkRoot, stored.nonce)
  if (crypto.callLinkKeys(secret).roomId !== stored.roomId) return null
  let info: MeetingInfo
  try {
    info = crypto.callLinkOpenInfo(secret, stored.info)
  } catch {
    return null
  }
  return {
    roomId: stored.roomId,
    createdAt: stored.createdAt,
    url: meetingUrl(chatOrigin, crypto.callLinkFragment(secret)),
    info,
    waitingRoom: stored.waitingRoom,
    nonce: stored.nonce,
    hostToken: crypto.callLinkHostToken(callLinkRoot, stored.nonce).hostToken,
  }
}

/** Make a meeting and register it with this server. */
export async function createOwnedCallLink(
  crypto: OwnerCallLinkCrypto,
  callLinkRoot: CallLinkRoot,
  info: MeetingInfo,
  chatOrigin: string,
  waitingRoom = false,
  /** The room id of one of this account's links that the new one replaces, at once. */
  replaces?: string,
): Promise<OwnedCallLink> {
  const nonce = crypto.callLinkNonce()
  const secret = crypto.callLinkOwnerSecret(callLinkRoot, nonce)
  const keys = crypto.callLinkKeys(secret)
  const { data } = await api.post<StoredCallLink>('/chat/call-links', {
    roomId: keys.roomId,
    nonce,
    accessTokenHash: keys.accessTokenHash,
    info: crypto.callLinkSealInfo(secret, info),
    hostTokenHash: crypto.callLinkHostToken(callLinkRoot, nonce).hostTokenHash,
    waitingRoom,
    ...(replaces ? { replaces } : {}),
  })
  const link = ownedCallLink(crypto, callLinkRoot, data, chatOrigin)
  if (!link) throw new Error('the server returned another meeting')
  return link
}

/** The account's meetings, newest first, as any of its devices derives them. */
export async function listOwnedCallLinks(crypto: OwnerCallLinkCrypto, callLinkRoot: CallLinkRoot, chatOrigin: string): Promise<OwnedCallLink[]> {
  const { data } = await api.get<{ links: StoredCallLink[] }>('/chat/call-links')
  return data.links.map((stored) => ownedCallLink(crypto, callLinkRoot, stored, chatOrigin)).filter((link): link is OwnedCallLink => link !== null)
}

/** Change what one of the account's meetings is called or when it is. */
export async function updateOwnedCallLinkInfo(crypto: OwnerCallLinkCrypto, link: Pick<OwnedCallLink, 'roomId' | 'url'>, info: MeetingInfo): Promise<void> {
  const fragment = callLinkFragmentOf(link.url)
  if (!fragment) throw new Error('not a meeting link')
  const secret = crypto.callLinkParse(fragment)
  await api.put(`/chat/call-links/${link.roomId}/info`, { info: crypto.callLinkSealInfo(secret, info) })
}

/**
 * Where Calendar opens a new event for a meeting (docs/plans/calendar.md,
 * E5c): the link and its title and time in the fragment, which no server
 * sees (the link's secret is in it). Calendar only fills the editor in.
 */
export function calendarMeetingUrl(calendarUrl: string, meeting: { url: string; info: MeetingInfo }): string {
  const params = new URLSearchParams({ meeting: meeting.url, title: meeting.info.title })
  if (meeting.info.startsAtMs) params.set('start', String(meeting.info.startsAtMs))
  if (meeting.info.durationMinutes) params.set('minutes', String(meeting.info.durationMinutes))
  return `${calendarUrl.replace(/#.*$/, '')}#${params.toString()}`
}
